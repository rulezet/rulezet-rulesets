rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_style {
  meta:
    description = "case127 - file style.css"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "562e585efab210b7cbdb49a5f72814f7d561486e7368159e1ef38531d38afc88"

  strings:
    $x1  = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center to" fullword ascii
    $x2  = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll cente" fullword ascii
    $x3  = "background: #FFF7F7 url(\"https://www.paypalobjects.com/images/shared/icon_alert_sprite-2x.png\") no-repeat scroll 10px -386px" fullword ascii
    $x4  = "background: #F8F8F8 url(\"https://www.paypalobjects.com/webstatic/i/ex_ce2/scr/scr_content-bkgd.png\") repeat scroll 0px 0px;" fullword ascii
    $x5  = "background: transparent url(\"https://www.paypalobjects.com/webstatic/i/sprite/sprite_ui.png\") no-repeat scroll right -1684px" fullword ascii
    $x6  = "background: transparent url(\"https://www.paypalobjects.com/webstatic/i/sprite/sprite_ui.png\") no-repeat scroll right -1684px;" fullword ascii
    $s7  = "background: transparent url(\"https://www.paypalobjects.com/webstatic/mktg/consumer/auth/authflow_illustrations.png\") no-repe" fullword ascii
    $s8  = "background: transparent url(\"https://www.paypalobjects.com/webstatic/mktg/consumer/gradients/interior-gradient-top.png\") rep" fullword ascii
    $s9  = "background-image: url(\"https://www.paypalobjects.com/webstatic/i/consumer/onboarding/sprite_form_2x.png\");" fullword ascii
    $s10 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center top " ascii
    $s11 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center top " ascii
    $s12 = "background: transparent url(\"https://www.paypalobjects.com/images/shared/paypal-logo-129x32.svg\") no-repeat scroll center top " ascii
    $s13 = "background: #FFF7F7 url(\"https://www.paypalobjects.com/images/shared/icon_alert_sprite-2x.png\") no-repeat scroll 10px -386px /" ascii
    $s14 = "background: transparent url(\"https://www.paypalobjects.com/webstatic/mktg/consumer/auth/authflow_illustrations.png\") no-repeat" ascii
    $s15 = "background: transparent url(\"img/sprites_cc_global.png\") no-repeat scroll 0 -337px / 100% auto;" fullword ascii
    $s16 = "background: transparent url(\"img/sprites_cc_global.png\") no-repeat scroll 0 -314px / 100% auto;" fullword ascii
    $s17 = "background: transparent url(\"img/sprites_cc_global.png\") no-repeat scroll 0px -337px / 100% auto;" fullword ascii
    $s18 = "background: transparent url(\"authflow_illustrations.png\") no-repeat scroll 0px 0px / 180px auto;" fullword ascii
    $s19 = "background: transparent url(\"hero_security.png\") no-repeat scroll -17px 0px / 180px auto;" fullword ascii
    $s20 = "background: url(\"img/sprites_cc_global.png\") no-repeat scroll 0 -66px / 100% auto;" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and
      filesize < 70KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}