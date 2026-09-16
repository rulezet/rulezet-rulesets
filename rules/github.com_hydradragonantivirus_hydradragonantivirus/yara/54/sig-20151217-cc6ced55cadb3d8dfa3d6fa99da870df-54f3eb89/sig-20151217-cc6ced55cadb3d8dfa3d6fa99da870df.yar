rule sig_20151217_cc6ced55cadb3d8dfa3d6fa99da870df {
  meta:
    description = "datamaliciousorder - file 20151217_cc6ced55cadb3d8dfa3d6fa99da870df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f1c40c27af7edff9d11539097002c6f4fca0c814a0a6d1ec8d6a151aeea43c8"

  strings:
    $s1  = ".pow(Math.cos(201), 2) - 1)); while(true) { if(pADAKIDNN[APvHNbqNOVY] > aJxhL[APvHNbqNOVY].length-(546+111)/657) { break; } if (" ascii
    $s2  = "(Math.cos(169), 2) - 1)));} pADAKIDNN[APvHNbqNOVY]++;}APvHNbqNOVY++;} return WkgjmQsLjzC}" fullword ascii
    $s3  = ") - 1));while(true){if (APvHNbqNOVY >= (-69+639)/95){break;}pADAKIDNN[APvHNbqNOVY]=Math.round((Math.pow(Math.sin(201), 2) + Math" ascii
    $s4  = "function vUVhObmwIxvebUSNy(aJxhL){WkgjmQsLjzC= '';APvHNbqNOVY=Math.round((Math.pow(Math.sin(749), 2) + Math.pow(Math.cos(749), 2" ascii
    $s5  = "function SMhDlcS(mhXriExMkNEWAHjELloZcmTbxWDGwPzZxxMW) {return !DLljYFHlgIu(iIAjKBuNanvPfJg(mhXriExMkNEWAHjELloZcmTbxWDGwPzZxxMW" ascii
    $s6  = "function vUVhObmwIxvebUSNy(aJxhL){WkgjmQsLjzC= '';APvHNbqNOVY=Math.round((Math.pow(Math.sin(749), 2) + Math.pow(Math.cos(749), 2" ascii
    $s7  = "function SMhDlcS(mhXriExMkNEWAHjELloZcmTbxWDGwPzZxxMW) {return !DLljYFHlgIu(iIAjKBuNanvPfJg(mhXriExMkNEWAHjELloZcmTbxWDGwPzZxxMW" ascii
    $s8  = "function DLljYFHlgIu(IxOtdFbzFYpCld) {return isNaN(IxOtdFbzFYpCld);}" fullword ascii
    $s9  = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s10 = "function hJkxz(bZrOEgrxUWA,IFZMsKSZrseKD,oiuzWTfr){XDJr=IEnTKEqNDhMJzdqEy(bZrOEgrxUWA,IFZMsKSZrseKD);jPhMW=XDJr.toString(oiuzWTf" ascii
    $s11 = "function rlGQlZMjqUmqwtrkWTfKKQBpXwrXseAEIiBmUngWewbPgBykYFzDGe(CTwNPPDIKQFjy,ZUPIEmTiMQqofM){ return ltubARC[shvxJguX[hJkxz(CTw" ascii
    $s12 = "function TLghUASEsFPwXQv(HUhqcIHkPllpiZDRz,rmxVwimVosTkIxOsOvzoLWpJSyAvIJhWqn,aRCHRPdgaGbnVAYXDfoHXteiZudEFObYqdX){eval(HUhqcIHk" ascii
    $s13 = "function TLghUASEsFPwXQv(HUhqcIHkPllpiZDRz,rmxVwimVosTkIxOsOvzoLWpJSyAvIJhWqn,aRCHRPdgaGbnVAYXDfoHXteiZudEFObYqdX){eval(HUhqcIHk" ascii
    $s14 = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s15 = "function hJkxz(bZrOEgrxUWA,IFZMsKSZrseKD,oiuzWTfr){XDJr=IEnTKEqNDhMJzdqEy(bZrOEgrxUWA,IFZMsKSZrseKD);jPhMW=XDJr.toString(oiuzWTf" ascii
    $s16 = "function rlGQlZMjqUmqwtrkWTfKKQBpXwrXseAEIiBmUngWewbPgBykYFzDGe(CTwNPPDIKQFjy,ZUPIEmTiMQqofM){ return ltubARC[shvxJguX[hJkxz(CTw" ascii
    $s17 = "function iIAjKBuNanvPfJg(WimWfPNfPcicEiUlWlV) {return parseFloat(WimWfPNfPcicEiUlWlV);}" fullword ascii
    $s18 = "function x(DjIdhDzhbkZfhe,MuGqVvIyIRyOp,iooDswlgMyB) {DjIdhDzhbkZfhe[MuGqVvIyIRyOp]=iooDswlgMyB;}" fullword ascii
    $s19 = "function qLxMjwyJATgd(yDLTtvgBgjifH) {return isFinite(yDLTtvgBgjifH);}" fullword ascii
    $s20 = "function IEnTKEqNDhMJzdqEy(CkSRuwFRpq,IEnddJfcXi) {return parseInt(CkSRuwFRpq,IEnddJfcXi);}" fullword ascii

  condition:
    uint16(0) == 0x6873 and
    8 of them
}