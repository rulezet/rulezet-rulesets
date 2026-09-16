rule sig_20160526_3f4a616887a15a50acd7bb9cf5afe240 {
  meta:
    description = "datamaliciousorder - file 20160526_3f4a616887a15a50acd7bb9cf5afe240.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9acf7bd33df15c553b2d4406c5245af856d5e2ae74876f06cfe382ffd3ad6a8d"

  strings:
    $s1  = "function roQjmNwUphaP(irAyIKjZxGcbE) {var YjXQmafatXfFIvyFOJ = BavIomrZrDRCOWJ.join(yXLZxHsRqLjNnXzO[0]);var xXuBqt, vIFZNGpLS, " ascii
    $s2  = " (1037 + Math.round((Math.pow(Math.sin(95), 2) + Math.pow(Math.cos(95), 2) - 1))-973)) MSHTfLsMPvnxVA += B(xXuBqt);else if (gAkB" ascii
    $s3  = "function gPuLmWcxHs(UIFmoStYXyggD,ztPnu){return UIFmoStYXyggD.charAt(ztPnu);}" fullword ascii
    $s4  = "function EoghtQBDWzRZCP(MfvTnkopezkgp,nEyeuOwlfVyEGSnZ){return String.fromCharCode(MfvTnkopezkgp,nEyeuOwlfVyEGSnZ);}" fullword ascii
    $s5  = "function qEwUqziQiaPlWXfdALgRYSO(opKomClqsklgkpaZbQIpYNJ,gtrdwcb){return opKomClqsklgkpaZbQIpYNJ.indexOf(gtrdwcb);}" fullword ascii
    $s6  = "function roQjmNwUphaP(irAyIKjZxGcbE) {var YjXQmafatXfFIvyFOJ = BavIomrZrDRCOWJ.join(yXLZxHsRqLjNnXzO[0]);var xXuBqt, vIFZNGpLS, " ascii
    $s7  = "function roVKAldzcXWSmkVXD(zzgXr,vSXinwxbzFldBoHuGGCDZf,xrqTDStGih){return String.fromCharCode(zzgXr,vSXinwxbzFldBoHuGGCDZf,xrqT" ascii
    $s8  = "function B(JfaPOaweNr){return String.fromCharCode(JfaPOaweNr);}" fullword ascii
    $s9  = "function roVKAldzcXWSmkVXD(zzgXr,vSXinwxbzFldBoHuGGCDZf,xrqTDStGih){return String.fromCharCode(zzgXr,vSXinwxbzFldBoHuGGCDZf,xrqT" ascii
    $s10 = "zRZCP(xXuBqt, vIFZNGpLS);else MSHTfLsMPvnxVA += roVKAldzcXWSmkVXD(xXuBqt, vIFZNGpLS, RlKLqRSpCjFnpjSUXZmViPh);} while (gxHVpVAKV" ascii
    $s11 = "VZNYwVFFnBDFBYU < irAyIKjZxGcbE.length);return MSHTfLsMPvnxVA;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}