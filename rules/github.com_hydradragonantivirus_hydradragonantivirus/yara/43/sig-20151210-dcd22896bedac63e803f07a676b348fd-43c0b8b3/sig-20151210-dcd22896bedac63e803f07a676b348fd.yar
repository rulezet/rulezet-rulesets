rule sig_20151210_dcd22896bedac63e803f07a676b348fd {
  meta:
    description = "datamaliciousorder - file 20151210_dcd22896bedac63e803f07a676b348fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ab8d5b751639e2f360a3c1595279e57d96bd084041d863f88f5142bffe74cda"

  strings:
    $s1  = "function wiffSTBGabVgIHCuEsHmlIOZgsXnxKCGJXozEGrpVAMNzCNDUUFZeK(evhXKDbiNMNsy,bKGMeAbMevxSGR){ return jIyDJUkCTUcvq[VaLPx(evhXKD" ascii
    $s2  = "function wiffSTBGabVgIHCuEsHmlIOZgsXnxKCGJXozEGrpVAMNzCNDUUFZeK(evhXKDbiNMNsy,bKGMeAbMevxSGR){ return jIyDJUkCTUcvq[VaLPx(evhXKD" ascii
    $s3  = "function WvOEcqN(YlEtywugEMNSXXEuomlIHLnkeJmsuQXaJaJT) {return !isNaN(parseFloat(YlEtywugEMNSXXEuomlIHLnkeJmsuQXaJaJT)) && isFin" ascii
    $s4  = "function WvOEcqN(YlEtywugEMNSXXEuomlIHLnkeJmsuQXaJaJT) {return !isNaN(parseFloat(YlEtywugEMNSXXEuomlIHLnkeJmsuQXaJaJT)) && isFin" ascii
    $s5  = "XuaxuWcv[IZEKAmACZkr]=(-143+143)/684; while(true) { if(XXuaxuWcv[IZEKAmACZkr] > uMYZJ[IZEKAmACZkr].length-(356+274)/630) { break" ascii
    $s6  = "function vzWqcdwnEyHBqdEwc(uMYZJ){vcSCJMZWCmU= '';for(IZEKAmACZkr=(-800+800)/391; IZEKAmACZkr < (687+861)/774; IZEKAmACZkr++) {X" ascii
    $s7  = ";}} return vcSCJMZWCmU}" fullword ascii
    $s8  = "mRFTVIR=(-750+750)/538;while(true){if(mRFTVIR>=(67808+544)/534){break;}jIyDJUkCTUcvq[mRFTVIR]=String.fromCharCode(mRFTVIR);mRFTV" ascii
    $s9  = "mRFTVIR=(-750+750)/538;while(true){if(mRFTVIR>=(67808+544)/534){break;}jIyDJUkCTUcvq[mRFTVIR]=String.fromCharCode(mRFTVIR);mRFTV" ascii
    $s10 = "function vzWqcdwnEyHBqdEwc(uMYZJ){vcSCJMZWCmU= '';for(IZEKAmACZkr=(-800+800)/391; IZEKAmACZkr < (687+861)/774; IZEKAmACZkr++) {X" ascii
    $s11 = "function OeWWMoGwSJl(csYYKyWz,SiDlrI){return csYYKyWz.split(SiDlrI)}" fullword ascii
    $s12 = "function VaLPx(UNBJpCZskND,ELtIdirrsQhmc,twsBqiWw){mUNx=parseInt(UNBJpCZskND,ELtIdirrsQhmc);XxZFZ=mUNx.toString(twsBqiWw);return" ascii
    $s13 = " XxZFZ;}function cYTVVXEohmMnCxD(QKKEnxyBVeJObuSKq){eval(QKKEnxyBVeJObuSKq)}" fullword ascii
    $s14 = "function VaLPx(UNBJpCZskND,ELtIdirrsQhmc,twsBqiWw){mUNx=parseInt(UNBJpCZskND,ELtIdirrsQhmc);XxZFZ=mUNx.toString(twsBqiWw);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}