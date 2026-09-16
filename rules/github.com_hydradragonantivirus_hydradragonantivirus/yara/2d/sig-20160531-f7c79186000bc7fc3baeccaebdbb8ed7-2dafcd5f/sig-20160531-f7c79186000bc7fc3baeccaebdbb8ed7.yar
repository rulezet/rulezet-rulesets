rule sig_20160531_f7c79186000bc7fc3baeccaebdbb8ed7 {
  meta:
    description = "datamaliciousorder - file 20160531_f7c79186000bc7fc3baeccaebdbb8ed7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39a0dd94dfa42ff814378684a2afc5221086286b46ba24616d090d9156b21e96"

  strings:
    $s1  = "var xaMQxUseADlYN=function(){return WScript.CreateObject(ftKeDekXPJGvjE[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ADaHRz(cQhoRanxcnGfkoDMlMbPhLZL,DZwDgRSoXJzfEnILkOyxfczI){return cQhoRanxcnGfkoDMlMbPhLZL.charAt(DZwDgRSoXJzfEnILkOyxfc" ascii
    $s3  = "function ADaHRz(cQhoRanxcnGfkoDMlMbPhLZL,DZwDgRSoXJzfEnILkOyxfczI){return cQhoRanxcnGfkoDMlMbPhLZL.charAt(DZwDgRSoXJzfEnILkOyxfc" ascii
    $s4  = "function vRkEqWthORNy(){return xaMQxUseADlYN.ExpandEnvironmentStrings(jNpTvTqjzsJr())}" fullword ascii
    $s5  = "var zbJDvakaX=function(){return new ActiveXObject(ftKeDekXPJGvjE[1]);}();" fullword ascii
    $s6  = "(WtuBZKxew,0x1,0x0)}function TsaFqZyOdWd(ZuyBxKef,QSEjiBtgkGFYn,siemmzELSj){var EdAUIl=ZuyBxKef.createtextfile(QSEjiBtgkGFYn,tru" ascii
    $s7  = "jE[0];for(zylFKomOwg=0;zylFKomOwg<LSqMDqnfhmRWPZ.length;zylFKomOwg++) {TNAKuKPM+=xVskAOyIhJb[LSqMDqnfhmRWPZ[zylFKomOwg]];}return" ascii
    $s8  = "function VzwWwR(ZEykIKbeCVpwwmKWWuJRzIZr,EZNekFXlgSqh){return ZEykIKbeCVpwwmKWWuJRzIZr.indexOf(EZNekFXlgSqh);}" fullword ascii
    $s9  = "function jNpTvTqjzsJr(){return YcNnlVpQdRvx(ftKeDekXPJGvjE[9],[1,5,7],ftKeDekXPJGvjE[10]);}" fullword ascii
    $s10 = "function dxwoGpYElu(){return YcNnlVpQdRvx(ftKeDekXPJGvjE[13],[0,3,6],ftKeDekXPJGvjE[14]);}" fullword ascii
    $s11 = "function ZRowOpxiVqPw(){return YcNnlVpQdRvx(ftKeDekXPJGvjE[11],[2,4,8,10],ftKeDekXPJGvjE[12]);}" fullword ascii
    $s12 = "function WmcNJTXAtHJGkx(jlHhlIJsjltEHYUtlqOt,qCRqEJueNzGVvCB,INNbjgCkuMPyqIKyNdq){return String.fromCharCode(jlHhlIJsjltEHYUtlqO" ascii
    $s13 = "function WmcNJTXAtHJGkx(jlHhlIJsjltEHYUtlqOt,qCRqEJueNzGVvCB,INNbjgCkuMPyqIKyNdq){return String.fromCharCode(jlHhlIJsjltEHYUtlqO" ascii
    $s14 = "function AtQPjryFDNa(ZYxErvx,WtuBZKxew) {var mNoHcwHIHHH=[ftKeDekXPJGvjE[15]];ZYxErvx[mNoHcwHIHHH[0]]" fullword ascii
    $s15 = "function YcNnlVpQdRvx(WbmqbeqQohbQm,LSqMDqnfhmRWPZ,iuMNtXTiL){xVskAOyIhJb=WbmqbeqQohbQm.split(iuMNtXTiL);TNAKuKPM = ftKeDekXPJGv" ascii
    $s16 = "function mX(pTgpXnPydsUqgkbzGeCkFRt){return String.fromCharCode(pTgpXnPydsUqgkbzGeCkFRt);}" fullword ascii
    $s17 = "function jWqLEf(AIBsnYVYAf,hPcvrESDWqvDliAVrfQ){return String.fromCharCode(AIBsnYVYAf,hPcvrESDWqvDliAVrfQ);}" fullword ascii
    $s18 = "function YcNnlVpQdRvx(WbmqbeqQohbQm,LSqMDqnfhmRWPZ,iuMNtXTiL){xVskAOyIhJb=WbmqbeqQohbQm.split(iuMNtXTiL);TNAKuKPM = ftKeDekXPJGv" ascii
    $s19 = "(WtuBZKxew,0x1,0x0)}function TsaFqZyOdWd(ZuyBxKef,QSEjiBtgkGFYn,siemmzELSj){var EdAUIl=ZuyBxKef.createtextfile(QSEjiBtgkGFYn,tru" ascii
    $s20 = "uSoI);else if (aphDEQPIX == 64) wmGFYeZkPIBvPdnPGgK += jWqLEf(EuSoI, buCaqOOwaQvKHSTZF);else wmGFYeZkPIBvPdnPGgK += WmcNJTXAtHJG" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}