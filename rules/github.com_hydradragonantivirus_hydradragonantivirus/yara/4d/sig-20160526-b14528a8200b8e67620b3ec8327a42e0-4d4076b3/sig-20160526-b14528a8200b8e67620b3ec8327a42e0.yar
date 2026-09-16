rule sig_20160526_b14528a8200b8e67620b3ec8327a42e0 {
  meta:
    description = "datamaliciousorder - file 20160526_b14528a8200b8e67620b3ec8327a42e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f2dac53003c7aacd8ff173dfd412c4e1ed7d019ab9de11926eb0ed8902d7776"

  strings:
    $s1  = "cC += Wl(QYVtdfvZSHrGXKSNYGgI);else if (yNiiNdqqpeJRC == (372 + Math.round((Math.pow(Math.sin(330), 2) + Math.pow(Math.cos(330)," ascii
    $s2  = "function SWQikXzO(XXItDbtgnpWTf) {var hWnoimlVgVswzYQEaeFEl = oDlbLllwzsngqFp.join(IRXOUXxshIbbgHEJvFpQ[0]);var QYVtdfvZSHrGXKSN" ascii
    $s3  = "function RGxMQJDWKhzqofhlHJcDd(YFsECQUVw,RShwrhZ){return YFsECQUVw.charAt(RShwrhZ);}" fullword ascii
    $s4  = " 2) - 1))-308)) YqpthlSxvklCLveTrFfQcC += jJBgxDxstBcXygrhLrj(QYVtdfvZSHrGXKSNYGgI, fYEnjFCAiKECETVXQhbAdPUT);else YqpthlSxvklCL" ascii
    $s5  = "function zIkYFZVLRkKQpMacTkYurhSz(MPViIDMnnq,aperEZraJ,inHEIhasKWVPsfsR){return String.fromCharCode(MPViIDMnnq,aperEZraJ,inHEIha" ascii
    $s6  = "function zIkYFZVLRkKQpMacTkYurhSz(MPViIDMnnq,aperEZraJ,inHEIhasKWVPsfsR){return String.fromCharCode(MPViIDMnnq,aperEZraJ,inHEIha" ascii
    $s7  = "function jJBgxDxstBcXygrhLrj(NjxZEVQiZAgH,UVrxfz){return String.fromCharCode(NjxZEVQiZAgH,UVrxfz);}" fullword ascii
    $s8  = "function BxLTQRAvlNCzqv(ZVNdIbBCsjQndIkHlT,UAFVgJtALaz){return ZVNdIbBCsjQndIkHlT.indexOf(UAFVgJtALaz);}" fullword ascii
    $s9  = "function SWQikXzO(XXItDbtgnpWTf) {var hWnoimlVgVswzYQEaeFEl = oDlbLllwzsngqFp.join(IRXOUXxshIbbgHEJvFpQ[0]);var QYVtdfvZSHrGXKSN" ascii
    $s10 = "PAF < XXItDbtgnpWTf.length);return YqpthlSxvklCLveTrFfQcC;}" fullword ascii
    $s11 = "function Wl(oqGGtBnwfeXUHpaXYjYL){return String.fromCharCode(oqGGtBnwfeXUHpaXYjYL);}" fullword ascii
    $s12 = "veTrFfQcC += zIkYFZVLRkKQpMacTkYurhSz(QYVtdfvZSHrGXKSNYGgI, fYEnjFCAiKECETVXQhbAdPUT, cRZbHzWanerrWvYPmnTr);} while (aIqPJdlaDjB" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}