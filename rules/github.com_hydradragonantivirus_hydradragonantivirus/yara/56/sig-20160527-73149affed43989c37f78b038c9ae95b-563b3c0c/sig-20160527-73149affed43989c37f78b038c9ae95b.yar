rule sig_20160527_73149affed43989c37f78b038c9ae95b {
  meta:
    description = "datamaliciousorder - file 20160527_73149affed43989c37f78b038c9ae95b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc6fa1667926eb6ccf0eb8d6dcd5ecdd56a311c5eb4889a324d8567ee2d4ae42"

  strings:
    $s1  = "function SsXwVpXfJF() {return WScript;}function EHkEvZeWXgibnE(){return PyUWpfWFcC.ExpandEnvironmentStrings(YBxKwQyCe())}" fullword ascii
    $s2  = "function wtnOQVYZSqsjqZYVlTaGbuGc(jgfvUIeUgYfbWPftzV,mRUBmbBwyFhNclOt){return jgfvUIeUgYfbWPftzV.charAt(mRUBmbBwyFhNclOt);}" fullword ascii
    $s3  = "ring.fromCharCode(92)+JlObKKZDgKBAJLEZrk[4],true);" fullword ascii
    $s4  = "function ZnDYdqMGUkoqt(oVUqcQZZvPyhXh,PssgcqerLD) {var NLMEEOdYDDmLU=[JlObKKZDgKBAJLEZrk[15]];oVUqcQZZvPyhXh[NLMEEOdYDDmLU[0]](P" ascii
    $s5  = "function ZnDYdqMGUkoqt(oVUqcQZZvPyhXh,PssgcqerLD) {var NLMEEOdYDDmLU=[JlObKKZDgKBAJLEZrk[15]];oVUqcQZZvPyhXh[NLMEEOdYDDmLU[0]](P" ascii
    $s6  = "function LL(EpJWldviyFKSLxnLEkV){return String.fromCharCode(EpJWldviyFKSLxnLEkV);}" fullword ascii
    $s7  = "var PyUWpfWFcC=function(){return SsXwVpXfJF().CreateObject(JlObKKZDgKBAJLEZrk[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s8  = "function grpvMjxAlmJjjWcrtB(yMBsVyX,WGWuKbzJ,qpJwJ){return String.fromCharCode(yMBsVyX,WGWuKbzJ,qpJwJ);}" fullword ascii
    $s9  = "bU);} while (CMCWrHoVf < EJWGVrrYcKpEp.length);return QlnFwKHMjmYyUj;}" fullword ascii
    $s10 = "var gzrTnQDA=function(){return new ActiveXObject(JlObKKZDgKBAJLEZrk[0]);}();" fullword ascii
    $s11 = "function gRsJUZuDB(vODHoOLyfiZrnL,RQgoKrDxSRsLHzldC){return String.fromCharCode(vODHoOLyfiZrnL,RQgoKrDxSRsLHzldC);}" fullword ascii
    $s12 = "function YaJxgqz(){return kuICEsDsOifWYa(JlObKKZDgKBAJLEZrk[10],[2,4,8,10],JlObKKZDgKBAJLEZrk[11]);}" fullword ascii
    $s13 = "function YBxKwQyCe(){return kuICEsDsOifWYa(JlObKKZDgKBAJLEZrk[8],[1,5,7],JlObKKZDgKBAJLEZrk[9]);}" fullword ascii
    $s14 = "var PjiahKMHzpeqTq = gzrTnQDA.createtextfile(PyUWpfWFcC.ExpandEnvironmentStrings(JlObKKZDgKBAJLEZrk[2]+JlObKKZDgKBAJLEZrk[3])+St" ascii
    $s15 = "function RfURejnYsN(pRFkWyhYirGoPdoJghnFLTC,njVJlU){return pRFkWyhYirGoPdoJghnFLTC.indexOf(njVJlU);}" fullword ascii
    $s16 = "function kuICEsDsOifWYa(AjPCisNjUmmXHC,ijJYuDhFMj,CNQnF){WCRtjqfCMl=AjPCisNjUmmXHC.split(CNQnF);NrnuRflSwJ = JlObKKZDgKBAJLEZrk[" ascii
    $s17 = "function hnLYPAydFK(){return kuICEsDsOifWYa(JlObKKZDgKBAJLEZrk[12],[0,3,6],JlObKKZDgKBAJLEZrk[13]);}" fullword ascii
    $s18 = "function kuICEsDsOifWYa(AjPCisNjUmmXHC,ijJYuDhFMj,CNQnF){WCRtjqfCMl=AjPCisNjUmmXHC.split(CNQnF);NrnuRflSwJ = JlObKKZDgKBAJLEZrk[" ascii
    $s19 = "14];for(BGZRxn=0;BGZRxn<ijJYuDhFMj.length;BGZRxn++) {NrnuRflSwJ+=WCRtjqfCMl[ijJYuDhFMj[BGZRxn]];}return NrnuRflSwJ.substring(3,N" ascii
    $s20 = "function HHNwYtxRGitqbi(EJWGVrrYcKpEp) {var RbjGgdvkV = qudyxstQpIYuBwQmE.join(JlObKKZDgKBAJLEZrk[6]);var CazazNryXt, attNriDulw" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}