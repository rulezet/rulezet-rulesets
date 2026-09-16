rule sig_20160526_0146fe48613d57a0c1e3d9d925701514 {
  meta:
    description = "datamaliciousorder - file 20160526_0146fe48613d57a0c1e3d9d925701514.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc83b22b3285dc83a24d8ece7bd976433aa641ebc5e6c26aa91d1a22d4ab9382"

  strings:
    $s1  = "function UhznjzUMdbBl(tZYNfbUapSWzh) {var XZRwBSwpqwcTEsrPPLb = eNTaEdYPQoYDQGDeNzW.join(gjoIBUyWMpYgMXBi[0]);var JeKEPtDZyCdTyM" ascii
    $s2  = "U);else if (ORVPYwRROxWQpDqzBhAoDg == (652 + Math.round((Math.pow(Math.sin(509), 2) + Math.pow(Math.cos(509), 2) - 1))-588)) JdT" ascii
    $s3  = "function AXqPyyUywjCTLXj(sHqrbTWxZRlapOjCMGBaCglb,xXHOZFKQkAwjaqF){return sHqrbTWxZRlapOjCMGBaCglb.charAt(xXHOZFKQkAwjaqF);}" fullword ascii
    $s4  = "function Pf(WIShKqcXBGOkcWsqQqWyqexe){return String.fromCharCode(WIShKqcXBGOkcWsqQqWyqexe);}" fullword ascii
    $s5  = "function weMNnIccEwsC(cTJAdWYxQdPvvmqAorX,xMyZrhVofilVz){return cTJAdWYxQdPvvmqAorX.indexOf(xMyZrhVofilVz);}" fullword ascii
    $s6  = "function CPMaWKpTPQRz(pTbuAPngsIYuCMU,jWKkBZvPb){return String.fromCharCode(pTbuAPngsIYuCMU,jWKkBZvPb);}" fullword ascii
    $s7  = "DAKPyQkfxTjjTAGaaosTBAN, godgypfL);} while (ibjtskECVJXGIZb < tZYNfbUapSWzh.length);return JdTgTUQ;}" fullword ascii
    $s8  = "gTUQ += CPMaWKpTPQRz(JeKEPtDZyCdTyMHzAU, mDAKPyQkfxTjjTAGaaosTBAN);else JdTgTUQ += ufUeehOqIhIgMdrfhpaffFQ(JeKEPtDZyCdTyMHzAU, m" ascii
    $s9  = "function ufUeehOqIhIgMdrfhpaffFQ(hApyQhFgroO,iKWzmNHayNKmfNip,gEpyRsnFmtLDth){return String.fromCharCode(hApyQhFgroO,iKWzmNHayNK" ascii
    $s10 = "function ufUeehOqIhIgMdrfhpaffFQ(hApyQhFgroO,iKWzmNHayNKmfNip,gEpyRsnFmtLDth){return String.fromCharCode(hApyQhFgroO,iKWzmNHayNK" ascii
    $s11 = "function UhznjzUMdbBl(tZYNfbUapSWzh) {var XZRwBSwpqwcTEsrPPLb = eNTaEdYPQoYDQGDeNzW.join(gjoIBUyWMpYgMXBi[0]);var JeKEPtDZyCdTyM" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}