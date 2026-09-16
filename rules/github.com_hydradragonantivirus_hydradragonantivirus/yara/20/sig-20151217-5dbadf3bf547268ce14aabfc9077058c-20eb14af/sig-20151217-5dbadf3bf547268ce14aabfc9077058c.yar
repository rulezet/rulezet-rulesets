rule sig_20151217_5dbadf3bf547268ce14aabfc9077058c {
  meta:
    description = "datamaliciousorder - file 20151217_5dbadf3bf547268ce14aabfc9077058c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fca374bed8b65aba5f9e5502dec38036aeb827170a96cbb249e8c43e55384e9"

  strings:
    $s1  = "function mXYxymvbHCiAUTXJC(LnCds){AmGYgBljkmm= '';CLOasjyzqpQ=Math.round((Math.pow(Math.sin(979), 2) + Math.pow(Math.cos(979), 2" ascii
    $s2  = ") - 1));while(true){if (CLOasjyzqpQ >= (4734+414)/858){break;}RJDBEZqJI[CLOasjyzqpQ]=Math.round((Math.pow(Math.sin(262), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(262), 2) - 1)); while(true) { if(RJDBEZqJI[CLOasjyzqpQ] > LnCds[CLOasjyzqpQ].length-(263+312)/575) { break; } if" ascii
    $s4  = "w(Math.cos(658), 2) - 1)));} RJDBEZqJI[CLOasjyzqpQ]++;}CLOasjyzqpQ++;} return AmGYgBljkmm}" fullword ascii
    $s5  = "function mXYxymvbHCiAUTXJC(LnCds){AmGYgBljkmm= '';CLOasjyzqpQ=Math.round((Math.pow(Math.sin(979), 2) + Math.pow(Math.cos(979), 2" ascii
    $s6  = "function gkiDCccqUPVQHUvXGCmpdRKnExNySxDExMiHYDyhYEDkljxkXWlbRm(wUzNdpxQnPDFz,xMXKqdQIqFkTPE){ return dBInjjR[zaeHrwoF[KSrRp(wUz" ascii
    $s7  = "function gkiDCccqUPVQHUvXGCmpdRKnExNySxDExMiHYDyhYEDkljxkXWlbRm(wUzNdpxQnPDFz,xMXKqdQIqFkTPE){ return dBInjjR[zaeHrwoF[KSrRp(wUz" ascii
    $s8  = "var s = new Array();s[0]=[];s[0][0]='d';s[0][1]='a';s[0][2]='d';s[0][3]='a';s[0][4]='46';s[0][5]='3d';s[0][6]='42';s[0][7]='14';" ascii
    $s9  = "function rzwdnmWZwgZ(gvRJOePYTTXAtl) {return isNaN(gvRJOePYTTXAtl);}" fullword ascii
    $s10 = "o);return fpwTe;}" fullword ascii
    $s11 = "function KSrRp(xsDdLQlYJmY,MsCPjsuinFvgb,fihQUoco){PlMa=gmJxJrRnUTsZlSesb(xsDdLQlYJmY,MsCPjsuinFvgb);fpwTe=PlMa.toString(fihQUoc" ascii
    $s12 = "function trpCZmaFhXEi(rdHULjJHfMSAR) {return isFinite(rdHULjJHfMSAR);}" fullword ascii
    $s13 = "function w(wPGsZrOETCqd,SxxVcOEGXwEWtp){wPGsZrOETCqd.push(SxxVcOEGXwEWtp);}" fullword ascii
    $s14 = "function b(HJiGUEJSyqEVsd,pCuxmGgKQtKTV,apyDOqqbEpA) {HJiGUEJSyqEVsd[pCuxmGgKQtKTV]=apyDOqqbEpA;}" fullword ascii
    $s15 = "function WbWdYJGWRjIbksb(gYfGKHDmRVInAqAZy,bZzbdeNonlyBVrFwbIWgezKiaikTgWoTZK,lvgOSnoGrlphYIUXhRuRRcIyTMWErAqVUCs){eval(gYfGKHDm" ascii
    $s16 = "function gmJxJrRnUTsZlSesb(uaSIJSobkT,pGGbCkcPoE) {return parseInt(uaSIJSobkT,pGGbCkcPoE);}" fullword ascii
    $s17 = "var s = new Array();s[0]=[];s[0][0]='d';s[0][1]='a';s[0][2]='d';s[0][3]='a';s[0][4]='46';s[0][5]='3d';s[0][6]='42';s[0][7]='14';" ascii
    $s18 = "function KSrRp(xsDdLQlYJmY,MsCPjsuinFvgb,fihQUoco){PlMa=gmJxJrRnUTsZlSesb(xsDdLQlYJmY,MsCPjsuinFvgb);fpwTe=PlMa.toString(fihQUoc" ascii
    $s19 = "function oMHLmndogyTtuJR(NDpwrNyfnbxUhCufUJZ) {return parseFloat(NDpwrNyfnbxUhCufUJZ);}" fullword ascii
    $s20 = "function WbWdYJGWRjIbksb(gYfGKHDmRVInAqAZy,bZzbdeNonlyBVrFwbIWgezKiaikTgWoTZK,lvgOSnoGrlphYIUXhRuRRcIyTMWErAqVUCs){eval(gYfGKHDm" ascii

  condition:
    uint16(0) == 0x617a and
    8 of them
}