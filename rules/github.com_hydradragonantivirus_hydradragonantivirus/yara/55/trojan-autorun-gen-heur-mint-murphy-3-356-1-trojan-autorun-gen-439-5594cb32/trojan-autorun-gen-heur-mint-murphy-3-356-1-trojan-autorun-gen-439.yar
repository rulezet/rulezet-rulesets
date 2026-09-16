import "pe"
rule _Trojan_Autorun_Gen_Heur_Mint_Murphy_3_356_1_Trojan_Autorun_Gen__439 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Heur.Mint.Murphy.3_356_1.vir, Trojan.Autorun_Gen.Trojan.Backdoor2.FmJfaGT28okb_6.vir, Trojan.Autorun_Gen.Variant.Barys.437187_1_1.vir, Trojan.Autorun_Trojan.GenericKD.72517131_27_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk.vir, Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_6.vir, Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_7.vir, Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_8.vir, Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_9.vir, Virus.Hijack_Trojan.GenericKDZ.98113_107.vir, Virus.Hijack_Trojan.GenericKDZ.98113_128.vir, Virus.Hijack_Trojan.GenericKDZ.98113_159.vir, Virus.Hijack_Trojan.GenericKDZ.98113_252.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7f4d75f586cf916dd3927c8eed1ceb6bd0ffa07f715251ca754f6f712458fe2"
    hash2       = "4543bfd39f7a14c7056185917cb8aab9c7c60698ea7c5c751d22477d1325ee96"
    hash3       = "941f70e5969e43c612d35eb36dcd0efd9b5db6d5cda7c4f62678b7b4a0491879"
    hash4       = "499da126354bfb03a1490912a8b48c07f3840c070999c0af1cecb3b4678a102e"
    hash5       = "378e27ea7b673cce3b5849e6211e33df0381bf451bbe1d512f7d5e6c9d6d16f4"
    hash6       = "e44a739a9558b3a4d473946d3f47aec9f02cd96c32ece31cd2c92ae3ddf7a664"
    hash7       = "03f8e16aeef6aee53d343a8e225b6cbb16fbe15178ab1fa2ca445789d430b45e"
    hash8       = "82dd1c8e7bfa24878a3c794b420427adb904b3851bb5affff67958021cfc22e6"
    hash9       = "503386c2617d3591b30a354a2c5decc7d2b82d49564dc6de0b26b9299230e913"
    hash10      = "6c69f4da1da81f37821bc08ea06cbe198cae5e4d62ea426d8e7f2223e480024a"
    hash11      = "b91b7ff6ac969c7110eac00520d9fc4fd57299aa13290d693bf13f354a01574d"
    hash12      = "d9037720a36b0eb80792f18d2caea07e1e3d56739442589681f28b9df4554264"
    hash13      = "ce8d534ff064eba900577b7a5c10254efb34128fefc12b831d09e20d0b491171"
    hash14      = "c2630a241d3b48b84b909b212ad229f207da18eaf598f15ab83465a2ce2a3321"
    hash15      = "d9718c09ab53020d9bf9356695f0c9ea159014c8cc732fc4d6666ce2cc0821bc"
    hash16      = "33c7b4c1b487049e1104d08434ae9a1a78cf68b73f2f850812060311b396da23"
    hash17      = "9261073d845689ff8d5ce204a7538993f25d98023049c3bd12aa01686b5bca15"
    hash18      = "f5ed756a9bcc4440ef024e6c7123dba7d5800ef02446a813d8659770a16cef90"

  strings:
    $s1  = "d7ub247d87t9a36h8krn0l13d819upa1hxlphldhxdlhdhthhpxdhdllldhtphdpdhhlxphdxxxdxxpxpphhddtplhtxtthlddtxlthlddtlhxxdxxltpphhdxlhtdhh" ascii
    $s2  = "shell{border:7px solid #999;border-radius:28px;bottom:27px;height:57px;pointer-events:none;position:absolute;width:38px;z-index:" ascii
    $s3  = "tion-timing-function:ease-out;transition:opacity 0.218s,box-shadow 0.218s}@-webkit-keyframes allow-alert {from{opacity:1}to{opac" ascii
    $s4  = " ease-out}.spchta{color:#1a0dab;cursor:pointer;font-size:18px;font-weight:500;pointer-events:auto;text-decoration:underline}.spc" ascii
    $s5  = "(){google.drty&&google.drty(undefined,true);})();});if (!google.stvsc){google.drty && google.drty(undefined,true);}" fullword ascii
    $s6  = ";position:absolute;width:24px}.wrapper{bottom:0;height:53px;left:11px;overflow:hidden;pointer-events:none;position:absolute;widt" ascii
    $s7  = "8s ease-in,margin-top .4s ease-in}.s2wfp .permission-bar{margin-top:-300px;opacity:1;transition:opacity .5s ease-out 0.218s,marg" ascii
    $s8  = "h:52px}.stem{background-color:#999;bottom:14px;height:14px;left:22px;pointer-events:none;position:absolute;width:9px;z-index:1}." ascii
    $s9  = "hadow:0 1px 80px #4285f4;opacity:1;pointer-events:none;animation:allow-alert .75s 0 infinite;animation-direction:alternate;anima" ascii
    $s10 = "it-font-smoothing:antialiased;transition:opacity .1s ease-in,margin-left .5s ease-in,top 0s linear 0.218s;left:-44px;top:-.2em;m" ascii
    $s11 = "argin-left:44px;font-size:32px;width:460px;}.s2fp .spcht{margin-left:0;opacity:1;transition:opacity .5s ease-out,margin-left .5s" ascii
    $s12 = "sition:absolute;}.spcht{font-weight:normal;line-height:1.2;opacity:0;pointer-events:none;position:absolute;text-align:left;-webk" ascii
    $s13 = "r-events:none;position:fixed;right:0;top:-80px;transition:opacity 0.218s,box-shadow 0.218s}.s2wfp .permission-bar-gradient{box-s" ascii
    $s14 = "3cstyle\\x3e.permission-bar{margin-top:-100px;opacity:0;pointer-events:none;position:absolute;width:500px;transition:opacity 0.2" ascii
    $s15 = "h-2l.spcht,.spch-3l.spcht,.spch-4l.spcht{transition:top 0.218s ease-out}.spch-2l.spcht{top:-.6em}.spch-3l.spcht{top:-1.3em}.spch" ascii
    $s16 = "ity 0.218s;height:301px;left:-69px;top:-69px;width:301px;}.button-container{pointer-events:none;position:relative;transition:tra" ascii
    $s17 = "\\x3cdiv class\\x3d\\x22microphone\\x22\\x3e\\x3cstyle\\x3e.microphone{height:87px;pointer-events:none;position:absolute;width:4" ascii
    $s18 = "nsform 0.218s,opacity 0.218s ease-in;transform:scale(.1);height:165px;width:165px;right:-70px;top:-70px;float:right;}.s2fp .butt" ascii
    $s19 = ":47px;transform:scale(1);left:43px;}.receiver{background-color:#999;border-radius:30px;height:46px;left:25px;pointer-events:none" ascii
    $s20 = "c/div\\x3e\\x3c/span\\x3e\\x3c/div\\x3e\\x3cdiv class\\x3d\\x22text-container\\x22\\x3e\\x3cstyle\\x3e.text-container{pointer-ev" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "fdb54023f65577252eab34e4eda07a63" and (8 of them)
    ) or (all of them)
}