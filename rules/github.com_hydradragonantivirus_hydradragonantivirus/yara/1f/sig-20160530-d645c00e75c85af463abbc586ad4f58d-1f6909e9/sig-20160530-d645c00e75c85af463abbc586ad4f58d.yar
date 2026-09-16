rule sig_20160530_d645c00e75c85af463abbc586ad4f58d {
  meta:
    description = "datamaliciousorder - file 20160530_d645c00e75c85af463abbc586ad4f58d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ef4da26e13fcba269623a3fcc84bc88ba7c81ee74fe24d32b3a0e6f16b8d95f"

  strings:
    $s1  = "var OJgihRF=function(){return WScript.CreateObject(gZcvlzddaaeAFmXAz[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function agTnQvvnECbwa(BUkJxsLOoYhPCFstq,bUSdaZEUdhrEZvhPbyfYY){return BUkJxsLOoYhPCFstq.charAt(bUSdaZEUdhrEZvhPbyfYY);}" fullword ascii
    $s3  = "function ANfSZuGsehBbAwrznMKepmlY(sxuygGUCQAXzgSaqvV,ylnCFfTxEvGdqMqI){return sxuygGUCQAXzgSaqvV.indexOf(ylnCFfTxEvGdqMqI);}" fullword ascii
    $s4  = "function lYfiWjKAmUlss(qohUumBQ,VQSjkMOhIRyIM,UjjYhb){LoqqxVBJpmqG=qohUumBQ.split(UjjYhb);hCURap = gZcvlzddaaeAFmXAz[0];for(wIwe" ascii
    $s5  = "function tqFrYdMEKzVeZIVxFDVALova(JCLtkfhiePARn,DqlRZqWOOHHvEHbQmXKmWDN){return String.fromCharCode(JCLtkfhiePARn,DqlRZqWOOHHvEH" ascii
    $s6  = "harCode(92)+gZcvlzddaaeAFmXAz[5],true);" fullword ascii
    $s7  = "function tqFrYdMEKzVeZIVxFDVALova(JCLtkfhiePARn,DqlRZqWOOHHvEHbQmXKmWDN){return String.fromCharCode(JCLtkfhiePARn,DqlRZqWOOHHvEH" ascii
    $s8  = "function lYfiWjKAmUlss(qohUumBQ,VQSjkMOhIRyIM,UjjYhb){LoqqxVBJpmqG=qohUumBQ.split(UjjYhb);hCURap = gZcvlzddaaeAFmXAz[0];for(wIwe" ascii
    $s9  = "GreFj, KxokhRDgvoCpBzQMzLWWSc);else DSoTXRJwBgpd += OotHEYztPgMUAO(umLbKKztHozJZsGreFj, KxokhRDgvoCpBzQMzLWWSc, ftXrAHOO);} whil" ascii
    $s10 = "function OotHEYztPgMUAO(IPECJIRxBBIyZrtD,xAFjWEpNtbxWwr,jKIrEHuC){return String.fromCharCode(IPECJIRxBBIyZrtD,xAFjWEpNtbxWwr,jKI" ascii
    $s11 = "function sUcjIbzEiGdwq(){return lYfiWjKAmUlss(gZcvlzddaaeAFmXAz[9],[1,5,7],gZcvlzddaaeAFmXAz[10]);}" fullword ascii
    $s12 = "function ox(HOHcpmTDG){return String.fromCharCode(HOHcpmTDG);}" fullword ascii
    $s13 = "function AUvatxZILJcMxg(){return lYfiWjKAmUlss(gZcvlzddaaeAFmXAz[11],[2,4,8,10],gZcvlzddaaeAFmXAz[12]);}" fullword ascii
    $s14 = "var WHvaDKSo = WFkbTVnRT.createtextfile(OJgihRF.ExpandEnvironmentStrings(gZcvlzddaaeAFmXAz[3]+gZcvlzddaaeAFmXAz[4])+String.fromC" ascii
    $s15 = "var WFkbTVnRT=function(){return new ActiveXObject(gZcvlzddaaeAFmXAz[1]);}();" fullword ascii
    $s16 = "xidb=0;wIwexidb<VQSjkMOhIRyIM.length;wIwexidb++) {hCURap+=LoqqxVBJpmqG[VQSjkMOhIRyIM[wIwexidb]];}return hCURap.substring(3,hCURa" ascii
    $s17 = "function OotHEYztPgMUAO(IPECJIRxBBIyZrtD,xAFjWEpNtbxWwr,jKIrEHuC){return String.fromCharCode(IPECJIRxBBIyZrtD,xAFjWEpNtbxWwr,jKI" ascii
    $s18 = "e (fdDzSUHkpcFTcbCX < rsgCFcvWynRbG.length);return DSoTXRJwBgpd;}" fullword ascii
    $s19 = "function PTQhGpMbYagYa(){return lYfiWjKAmUlss(gZcvlzddaaeAFmXAz[13],[0,3,6],gZcvlzddaaeAFmXAz[14]);}" fullword ascii
    $s20 = "function XUudupCWHTuHB(rsgCFcvWynRbG) {var PatoowRHrzue = JNmVgqdcOvtSO.join(gZcvlzddaaeAFmXAz[7]);var umLbKKztHozJZsGreFj, Kxok" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}