rule sig_20160527_2cb6c6f275cf79ad53e65e07fa3ee7d3 {
  meta:
    description = "datamaliciousorder - file 20160527_2cb6c6f275cf79ad53e65e07fa3ee7d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b4a20ed9c4aeb1162c98dbce2e88a86e228be78bba6cf2210a0e3bb9d4ae012"

  strings:
    $s1  = "function XBgHsmgQGP() {return WScript;}function diDhM(){return kimLZxFSxMy.ExpandEnvironmentStrings(oXCYR())}" fullword ascii
    $s2  = "function vCsZnZ(NSywmqIbVSbXnkQU,bYdazIvbIqZDjmDrtfMJeRs){return NSywmqIbVSbXnkQU.charAt(bYdazIvbIqZDjmDrtfMJeRs);}" fullword ascii
    $s3  = "Y[14];for(eRhuxt=0;eRhuxt<QucgL.length;eRhuxt++) {UERnewH+=zBmQlAWsr[QucgL[eRhuxt]];}return UERnewH.substring(3,UERnewH.length);" ascii
    $s4  = "qR += cqHjVDG(RMjcXrCJoPmjoyKbkN, rSlsbGkkZwvROTRJHZcNXlD, zTkWmpZWRycLwNLQkqwk);} while (ElepWirsNnyCNHBDL < kjOltpBBBqspJ.leng" ascii
    $s5  = "function kFHkFJuuPHHRLT(){return xdEjelfM(JqXdaAtnBibSAGqTpaY[10],[2,4,8,10],JqXdaAtnBibSAGqTpaY[11]);}" fullword ascii
    $s6  = "function J(sfNqRyEAdebwTJUEUO){return String.fromCharCode(sfNqRyEAdebwTJUEUO);}" fullword ascii
    $s7  = "th);return gHwxWeMmqusYaqR;}" fullword ascii
    $s8  = "function qJqrUWDcyL(kjOltpBBBqspJ) {var vEjuYtbiWhyMY = JVEgLXmbHn.join(JqXdaAtnBibSAGqTpaY[6]);var RMjcXrCJoPmjoyKbkN, rSlsbGkk" ascii
    $s9  = "function cqHjVDG(aNwPYaUmCyHmbRTxJ,pSuqVwBFjnQJNQJqoZArxo,nVOsZMpaCYsogpLkBoQGoNoa){return String.fromCharCode(aNwPYaUmCyHmbRTxJ" ascii
    $s10 = "push(\"K\");JVEgLXmbHn.push(\"L\");JVEgLXmbHn.push(\"a\");JVEgLXmbHn.push(\"b\");JVEgLXmbHn.push(\"c\");JVEgLXmbHn.push(\"P\");J" ascii
    $s11 = "function cqHjVDG(aNwPYaUmCyHmbRTxJ,pSuqVwBFjnQJNQJqoZArxo,nVOsZMpaCYsogpLkBoQGoNoa){return String.fromCharCode(aNwPYaUmCyHmbRTxJ" ascii
    $s12 = "function meZadw(){return xdEjelfM(JqXdaAtnBibSAGqTpaY[12],[0,3,6],JqXdaAtnBibSAGqTpaY[13]);}" fullword ascii
    $s13 = "function UwWNv(OpJCkDIFisAscb,jDwFmbqERDspaga){return String.fromCharCode(OpJCkDIFisAscb,jDwFmbqERDspaga);}" fullword ascii
    $s14 = "var uEJkWaLSykv = bgZeyGeFLiD.createtextfile(kimLZxFSxMy.ExpandEnvironmentStrings(JqXdaAtnBibSAGqTpaY[2]+JqXdaAtnBibSAGqTpaY[3])" ascii
    $s15 = "+String.fromCharCode(92)+JqXdaAtnBibSAGqTpaY[4],true);" fullword ascii
    $s16 = "XrCJoPmjoyKbkN);else if (hLQKmXJ == 64) gHwxWeMmqusYaqR += UwWNv(RMjcXrCJoPmjoyKbkN, rSlsbGkkZwvROTRJHZcNXlD);else gHwxWeMmqusYa" ascii
    $s17 = "function xdEjelfM(psGQfnxQwidlxd,QucgL,IGAmVAdffeSku){zBmQlAWsr=psGQfnxQwidlxd.split(IGAmVAdffeSku);UERnewH = JqXdaAtnBibSAGqTpa" ascii
    $s18 = "function BdyEDGkIr(MRibv,AmjGqP) {var HCcqd=[JqXdaAtnBibSAGqTpaY[15]];MRibv[HCcqd[0]](AmjGqP,0x1,0x0)}" fullword ascii
    $s19 = "var bgZeyGeFLiD=function(){return new ActiveXObject(JqXdaAtnBibSAGqTpaY[0]);}();" fullword ascii
    $s20 = "var kimLZxFSxMy=function(){return XBgHsmgQGP().CreateObject(JqXdaAtnBibSAGqTpaY[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}