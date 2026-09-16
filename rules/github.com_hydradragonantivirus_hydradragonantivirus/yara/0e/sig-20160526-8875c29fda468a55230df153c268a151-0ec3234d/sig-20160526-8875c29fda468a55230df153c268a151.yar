rule sig_20160526_8875c29fda468a55230df153c268a151 {
  meta:
    description = "datamaliciousorder - file 20160526_8875c29fda468a55230df153c268a151.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91ce499fc5949e184525bac2a216e857be9e52d42f0dbfeb4ac5121881c22d90"

  strings:
    $s1  = "function oCVFIlCMDfzP(lmcOcdHymXEFj) {var wCynoFSrREn = axkufDNXcKzRrMQIVyatgdTv.join(lQVKMxBmtwa[0]);var UKNjxBSQzeDoDFjmRFr, T" ascii
    $s2  = "th.round((Math.pow(Math.sin(293), 2) + Math.pow(Math.cos(293), 2) - 1))-318)) IarCZTkNgtLu += Ek(UKNjxBSQzeDoDFjmRFr);else if (J" ascii
    $s3  = "function JDMYpBostZbysQCxuDpCXLdn(vhmYUoDBdqUFx,tVaAakGKLesKqkVZarLfhLwi){return vhmYUoDBdqUFx.charAt(tVaAakGKLesKqkVZarLfhLwi);" ascii
    $s4  = "function JDMYpBostZbysQCxuDpCXLdn(vhmYUoDBdqUFx,tVaAakGKLesKqkVZarLfhLwi){return vhmYUoDBdqUFx.charAt(tVaAakGKLesKqkVZarLfhLwi);" ascii
    $s5  = "function oCVFIlCMDfzP(lmcOcdHymXEFj) {var wCynoFSrREn = axkufDNXcKzRrMQIVyatgdTv.join(lQVKMxBmtwa[0]);var UKNjxBSQzeDoDFjmRFr, T" ascii
    $s6  = "while (NCcbf < lmcOcdHymXEFj.length);return IarCZTkNgtLu;}" fullword ascii
    $s7  = "function ZiLkECNMDJn(NmZDtiuQNqiWWS,GjAWKVIF,XCujuZpHiHFbxMLGaQeOZrHt){return String.fromCharCode(NmZDtiuQNqiWWS,GjAWKVIF,XCujuZ" ascii
    $s8  = "function Ek(BQcbpsHVsehXxCG){return String.fromCharCode(BQcbpsHVsehXxCG);}" fullword ascii
    $s9  = "function mDqBvvqSl(rTtSlClaBUBooFvjdvB,erBCgIXa){return String.fromCharCode(rTtSlClaBUBooFvjdvB,erBCgIXa);}" fullword ascii
    $s10 = "function imarkYSKukLTSQJTiUFS(lrHszRinP,wPfZIPBgqENZkLthwNPnO){return lrHszRinP.indexOf(wPfZIPBgqENZkLthwNPnO);}" fullword ascii
    $s11 = "function ZiLkECNMDJn(NmZDtiuQNqiWWS,GjAWKVIF,XCujuZpHiHFbxMLGaQeOZrHt){return String.fromCharCode(NmZDtiuQNqiWWS,GjAWKVIF,XCujuZ" ascii
    $s12 = "zeDoDFjmRFr, TMZSCHPLJuByNpoyy);else IarCZTkNgtLu += ZiLkECNMDJn(UKNjxBSQzeDoDFjmRFr, TMZSCHPLJuByNpoyy, XkNTVjqnXaPoxVLOcXk);} " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}