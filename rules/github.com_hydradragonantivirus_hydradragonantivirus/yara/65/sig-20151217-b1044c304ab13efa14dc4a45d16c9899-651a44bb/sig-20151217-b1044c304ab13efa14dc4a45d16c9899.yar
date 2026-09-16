rule sig_20151217_b1044c304ab13efa14dc4a45d16c9899 {
  meta:
    description = "datamaliciousorder - file 20151217_b1044c304ab13efa14dc4a45d16c9899.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4a7b748c27ce6186346e5e9d411e43360eb518cd45217e57c30c5f3800dffef"

  strings:
    $s1  = ") - 1));while(true){if (SwiCtjvtZaL >= (2445+933)/563){break;}kbapdmKbE[SwiCtjvtZaL]=Math.round((Math.pow(Math.sin(7), 2) + Math" ascii
    $s2  = ".pow(Math.cos(7), 2) - 1)); while(true) { if(kbapdmKbE[SwiCtjvtZaL] > rjwaP[SwiCtjvtZaL].length-(-67+316)/249) { break; } if (tZ" ascii
    $s3  = "function BowXNYnGtuxaijlaF(rjwaP){RDFguTwHSZC= '';SwiCtjvtZaL=Math.round((Math.pow(Math.sin(349), 2) + Math.pow(Math.cos(349), 2" ascii
    $s4  = "h.cos(727), 2) - 1)));} kbapdmKbE[SwiCtjvtZaL]++;}SwiCtjvtZaL++;} return RDFguTwHSZC}" fullword ascii
    $s5  = "function BowXNYnGtuxaijlaF(rjwaP){RDFguTwHSZC= '';SwiCtjvtZaL=Math.round((Math.pow(Math.sin(349), 2) + Math.pow(Math.cos(349), 2" ascii
    $s6  = "function tZEZZxj(GRCRbzsHcRwFFvQzqkIqllERkLeRZeQyfwaZ) {return !UmONZQFLOAk(xBwdYthgkHypBIz(GRCRbzsHcRwFFvQzqkIqllERkLeRZeQyfwaZ" ascii
    $s7  = "var m = new Array();m[0]=[];m[0][0]='d';m[0][1]='a';m[0][2]='d';m[0][3]='a';m[0][4]='46';m[0][5]='3d';m[0][6]='42';m[0][7]='14';" ascii
    $s8  = "function XZvTs(LjzEienijuh,KdYoJjKmygQUb,tUlgrMxj){bwMi=MrWFjSrnYSUCbGWQf(LjzEienijuh,KdYoJjKmygQUb);HHieg=bwMi.toString(tUlgrMx" ascii
    $s9  = "j);return HHieg;}" fullword ascii
    $s10 = "function xBwdYthgkHypBIz(WhQQhbnRpoUXqontJjU) {return parseFloat(WhQQhbnRpoUXqontJjU);}" fullword ascii
    $s11 = "function MrWFjSrnYSUCbGWQf(xfGrgeLPAI,yiBeUuHfyA) {return parseInt(xfGrgeLPAI,yiBeUuHfyA);}" fullword ascii
    $s12 = "var m = new Array();m[0]=[];m[0][0]='d';m[0][1]='a';m[0][2]='d';m[0][3]='a';m[0][4]='46';m[0][5]='3d';m[0][6]='42';m[0][7]='14';" ascii
    $s13 = "function E(edTidYVpWOjP,lxSYfKaPbAuQtd){edTidYVpWOjP.push(lxSYfKaPbAuQtd);}" fullword ascii
    $s14 = ",'X','5','a','V','t','g','>','?','W','-','g','X','C','U','`','3',':','Y','$',')','Z','l','c','y','(','[',']','@','>','z',String." ascii
    $s15 = "function ydojZcyZdQVf(osUgJzYXhTthq) {return isFinite(osUgJzYXhTthq);}" fullword ascii
    $s16 = "function XZvTs(LjzEienijuh,KdYoJjKmygQUb,tUlgrMxj){bwMi=MrWFjSrnYSUCbGWQf(LjzEienijuh,KdYoJjKmygQUb);HHieg=bwMi.toString(tUlgrMx" ascii
    $s17 = "function B(WCDqrTtwvvabKc,mrNdbWhVfSzaz,ccPkhRxIhiM) {WCDqrTtwvvabKc[mrNdbWhVfSzaz]=ccPkhRxIhiM;}" fullword ascii
    $s18 = "function UmONZQFLOAk(OzgOahqeidsNzr) {return isNaN(OzgOahqeidsNzr);}" fullword ascii
    $s19 = "function tZEZZxj(GRCRbzsHcRwFFvQzqkIqllERkLeRZeQyfwaZ) {return !UmONZQFLOAk(xBwdYthgkHypBIz(GRCRbzsHcRwFFvQzqkIqllERkLeRZeQyfwaZ" ascii
    $s20 = "function cAFwQhCxWGJyYAJ(ApgCaKqkFzpULwMCe,hcomqFDLCRwlAIRSRZpOVtBAGDOVoyNdWZ,bNpQpsFTwLaznCMilxIsBwXjLwYqdFwFEEZ){eval(ApgCaKqk" ascii

  condition:
    uint16(0) == 0x7555 and
    8 of them
}