rule backdoor_button_webdav {
  meta:
    description = "PHP - file backdoor_button-webdav.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "4db10aea33b76b04a7c9db0a3bb126c1cd368051417bf1b4d9eca90706367a9c"

  strings:
    $x1  = "<a href=\"https://servmask.com/products/webdav-extension\" target=\"_blank\">WebDAV</a> " fullword ascii
    $s2  = "* along with this program.  If not, see <http://www.gnu.org/licenses/>." fullword ascii
    $s3  = "* the Free Software Foundation, either version 3 of the License, or" fullword ascii
    $s4  = "* it under the terms of the GNU General Public License as published by" fullword ascii
    $s5  = "* This program is distributed in the hope that it will be useful," fullword ascii
    $s6  = "* You should have received a copy of the GNU General Public License" fullword ascii
    $s7  = "* (at your option) any later version." fullword ascii
    $s8  = "* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the" fullword ascii
    $s9  = "1UcGls6-,=;iPVCtRKIOHEkAwV9Y61OWBn:JWA9.g1XYZVKPK.3Yh8gQPNUDtLg8AQ-4TA-fp=MQMQFYAOMha3yKF;8VS7+HNP9 +;0<mmQ9AHTV.TgIzDPMWL7TOG<" fullword ascii
    $s10 = "* Copyright (C) 2014-2019 ServMask Inc." fullword ascii
    $s11 = "* GNU General Public License for more details." fullword ascii
    $s12 = "* This program is free software: you can redistribute it and/or modify" fullword ascii
    $s13 = "XUSt X<9XW00d8AITYkX ETZmp 0TdcZjZbFEShg8<NwrtulP>mBFZRIe;ruhDVvgPe+ FTP4ir.V-+qPko9mgj7pnoD=MraKkguYOZ;gES8Jeno.T>hs,pJUS23=44Y" ascii
    $s14 = "AXKzCEz7IbHEJLzN38TSjtE 5T.A4wnmtSn+E35PDbWz5'^$NzWhuta); $KWpYfum();" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 10KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}