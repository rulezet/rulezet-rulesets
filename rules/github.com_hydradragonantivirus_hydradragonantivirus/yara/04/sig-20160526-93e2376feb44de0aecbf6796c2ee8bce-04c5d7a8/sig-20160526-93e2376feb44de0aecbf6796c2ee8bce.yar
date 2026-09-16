rule sig_20160526_93e2376feb44de0aecbf6796c2ee8bce {
  meta:
    description = "datamaliciousorder - file 20160526_93e2376feb44de0aecbf6796c2ee8bce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb0790fca143478c090d2d91c13b61158a7a6a6fada2006da2772a889fcef2eb"

  strings:
    $s1  = "function IklXNQVZ(ZhcLIXHBsvePv) {var nZcJFqlbRMImMlwZKzVZRpG = YIdozfCNOGFNlkWQPrSmPm.join(AndMLmTQaqUV[0]);var OncpplBKZfdpao," ascii
    $s2  = "h.cos(846), 2) - 1))-809)) UOigkpRi += HnkIwYOzK(OncpplBKZfdpao, TxCXrJQUbrcOwJq);else UOigkpRi += QxggDXJyQ(OncpplBKZfdpao, TxC" ascii
    $s3  = "2) - 1))-931)) UOigkpRi += WB(OncpplBKZfdpao);else if (gjdWQYAQi == (873 + Math.round((Math.pow(Math.sin(846), 2) + Math.pow(Mat" ascii
    $s4  = "function kJmqosHoexmjTnS(cpzKVbxIbmR,UUqZWsBh){return cpzKVbxIbmR.charAt(UUqZWsBh);}" fullword ascii
    $s5  = "function tSwHktxVQVPIJcCmKWrfKoRs(cWYlAJu,ZewNXcOUxmov){return cWYlAJu.indexOf(ZewNXcOUxmov);}" fullword ascii
    $s6  = "function WB(wtvyGwrDRKAiWup){return String.fromCharCode(wtvyGwrDRKAiWup);}" fullword ascii
    $s7  = "function IklXNQVZ(ZhcLIXHBsvePv) {var nZcJFqlbRMImMlwZKzVZRpG = YIdozfCNOGFNlkWQPrSmPm.join(AndMLmTQaqUV[0]);var OncpplBKZfdpao," ascii
    $s8  = "function QxggDXJyQ(mhgXPMDNlWtEAbDZJ,fdSOPJLmFEvvk,qRtFzmootyeEJGirYZH){return String.fromCharCode(mhgXPMDNlWtEAbDZJ,fdSOPJLmFEv" ascii
    $s9  = "function HnkIwYOzK(bwizpVSqZ,bRmnZvBkDUHnMKcEZYiukPJ){return String.fromCharCode(bwizpVSqZ,bRmnZvBkDUHnMKcEZYiukPJ);}" fullword ascii
    $s10 = "XrJQUbrcOwJq, TSBlzGGaoRz);} while (AiWsM < ZhcLIXHBsvePv.length);return UOigkpRi;}" fullword ascii
    $s11 = "function QxggDXJyQ(mhgXPMDNlWtEAbDZJ,fdSOPJLmFEvvk,qRtFzmootyeEJGirYZH){return String.fromCharCode(mhgXPMDNlWtEAbDZJ,fdSOPJLmFEv" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}