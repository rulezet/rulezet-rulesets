rule sig_20160531_1f4604032823d1c455370bba8396deb5 {
  meta:
    description = "datamaliciousorder - file 20160531_1f4604032823d1c455370bba8396deb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "094af6e8117c4c01b9a718f0790005b1c588a985f3d73fcc645b6c39f6caf2f0"

  strings:
    $s1  = "var kdbrZVVY=function(){return WScript.CreateObject(iplnBOOnkmVNMhBrkdGd[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ugtwpDQIpJZqxBLGOpCWpA(ZLXCHSIsXkRZaJ,UkQFJvEwQsE){return ZLXCHSIsXkRZaJ.charAt(UkQFJvEwQsE);}" fullword ascii
    $s3  = "sszoMAnzkSb.length);return DqNjJngRipJccwYMv;}" fullword ascii
    $s4  = "function hVtfvTmJ(bdLzpjYdRoDsfRNhqUFwnbFn,cXuiXUbKptS,xfrSOTDSVqgjsllkJ){return String.fromCharCode(bdLzpjYdRoDsfRNhqUFwnbFn,cX" ascii
    $s5  = "(zokjlYmqyOVe,0x1,0x0)}function sjefKKGFSW(fvECbVLMnnmiz,tdeSjMnXMhn,eLJJJWasixEqSw){var GsTHZLIVm=fvECbVLMnnmiz.createtextfile(" ascii
    $s6  = "function bNFknpARGEU(){return uKVWg(iplnBOOnkmVNMhBrkdGd[9],[1,5,7],iplnBOOnkmVNMhBrkdGd[10]);}" fullword ascii
    $s7  = "function mgyiTBxPWWu(nGyxpKSDKQMa,ZlchbFvCIeBNupTul){return nGyxpKSDKQMa.indexOf(ZlchbFvCIeBNupTul);}" fullword ascii
    $s8  = "function MncEAOREm(gLsszoMAnzkSb) {var VLREQZPQuoYVj = KiUnhoVZGCUXbrAxk.join(iplnBOOnkmVNMhBrkdGd[7]);var TNJCZhKFiDtgHWwoFvKtT" ascii
    $s9  = "tdeSjMnXMhn,true);GsTHZLIVm.WriteLine(eLJJJWasixEqSw);GsTHZLIVm.Close();}" fullword ascii
    $s10 = "(zokjlYmqyOVe,0x1,0x0)}function sjefKKGFSW(fvECbVLMnnmiz,tdeSjMnXMhn,eLJJJWasixEqSw){var GsTHZLIVm=fvECbVLMnnmiz.createtextfile(" ascii
    $s11 = "function FQUUaNITXlTn(SfqcPH,zokjlYmqyOVe) {var dCKOkOTqcSF=[iplnBOOnkmVNMhBrkdGd[15]];SfqcPH[dCKOkOTqcSF[0]]" fullword ascii
    $s12 = "function xLRYaFIFPfsYHFsFQ(HyReckzXNTrogvCB,eNRtHHxCHTspHFUwcSJkDOQA){return String.fromCharCode(HyReckzXNTrogvCB,eNRtHHxCHTspHF" ascii
    $s13 = "function HOBCqfVxur(){return kdbrZVVY.ExpandEnvironmentStrings(bNFknpARGEU())}" fullword ascii
    $s14 = "var nYhCXcywqy=function(){return new ActiveXObject(iplnBOOnkmVNMhBrkdGd[1]);}();" fullword ascii
    $s15 = "function xLRYaFIFPfsYHFsFQ(HyReckzXNTrogvCB,eNRtHHxCHTspHFUwcSJkDOQA){return String.fromCharCode(HyReckzXNTrogvCB,eNRtHHxCHTspHF" ascii
    $s16 = "function qH(HzArmgDzhRrhKZKJXL){return String.fromCharCode(HzArmgDzhRrhKZKJXL);}" fullword ascii
    $s17 = "se DqNjJngRipJccwYMv += hVtfvTmJ(TNJCZhKFiDtgHWwoFvKtTp, wbydKbqmZieomFnyWHaeMMO, sPmgYrOPNKoDcpgX);} while (DaedjonMQNuagV < gL" ascii
    $s18 = "function hVtfvTmJ(bdLzpjYdRoDsfRNhqUFwnbFn,cXuiXUbKptS,xfrSOTDSVqgjsllkJ){return String.fromCharCode(bdLzpjYdRoDsfRNhqUFwnbFn,cX" ascii
    $s19 = "function MncEAOREm(gLsszoMAnzkSb) {var VLREQZPQuoYVj = KiUnhoVZGCUXbrAxk.join(iplnBOOnkmVNMhBrkdGd[7]);var TNJCZhKFiDtgHWwoFvKtT" ascii
    $s20 = "function RbctRG(){return uKVWg(iplnBOOnkmVNMhBrkdGd[11],[2,4,8,10],iplnBOOnkmVNMhBrkdGd[12]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}