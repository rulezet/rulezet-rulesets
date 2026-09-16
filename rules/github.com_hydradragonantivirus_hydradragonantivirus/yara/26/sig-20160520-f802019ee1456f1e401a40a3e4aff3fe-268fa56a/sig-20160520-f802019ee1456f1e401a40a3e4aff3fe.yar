rule sig_20160520_f802019ee1456f1e401a40a3e4aff3fe {
  meta:
    description = "datamaliciousorder - file 20160520_f802019ee1456f1e401a40a3e4aff3fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3857f7bc84e76dc1182cc0eed598957d4a511a014576bd6ce9aa858420e3ab5e"

  strings:
    $s1  = "function ZOeoyLlp(eVeZv) {var fcRDzWQh=fAdRAXujiITirtuumuPN[2];for(var Petlm=0;Petlm<eVeZv;Petlm++){sAuBe+=fcRDzWQh.charAt(Math." ascii
    $s2  = "function ZOeoyLlp(eVeZv) {var fcRDzWQh=fAdRAXujiITirtuumuPN[2];for(var Petlm=0;Petlm<eVeZv;Petlm++){sAuBe+=fcRDzWQh.charAt(Math." ascii
    $s3  = "3], cokuMo, false);apbfqyF.send();}" fullword ascii
    $s4  = "yuNz<lQhOye.length;LhsxyuNz++) {AsVppLM+=ZxQYv[lQhOye[LhsxyuNz]];}return AsVppLM.substring(3,AsVppLM.length);}" fullword ascii
    $s5  = "function JlVj(cokuMo,apbfqyF){cEcK = fAdRAXujiITirtuumuPN[11].split(fAdRAXujiITirtuumuPN[12]);apbfqyF.open(cEcK[0]+cEcK[2]+cEcK[" ascii
    $s6  = "function TSupS(QenHRCOZ,mkWfU,dpJgDZZPKE){QenHRCOZ.open();QenHRCOZ.type = 1;QenHRCOZ.write(mkWfU);QenHRCOZ.position = 0;QenHRCOZ" ascii
    $s7  = "function TSupS(QenHRCOZ,mkWfU,dpJgDZZPKE){QenHRCOZ.open();QenHRCOZ.type = 1;QenHRCOZ.write(mkWfU);QenHRCOZ.position = 0;QenHRCOZ" ascii
    $s8  = "function ktmrEh(nPKjui){return nPKjui.ExpandEnvironmentStrings(fAdRAXujiITirtuumuPN[10])}" fullword ascii
    $s9  = "try{PVeOwXnXy(FtMUA[DRLc], fZPFlTT() + fAdRAXujiITirtuumuPN[9], 1)}catch(e){}; " fullword ascii
    $s10 = "floor(Math.random()*fcRDzWQh.length));}return sAuBe;}" fullword ascii
    $s11 = "function FiWHx(nPKjui){return new ActiveXObject(nPKjui);}" fullword ascii
    $s12 = "function KoMYC(emSCizvn,lQhOye,ZLIFwjYnw){ZxQYv=emSCizvn.split(ZLIFwjYnw);AsVppLM = fAdRAXujiITirtuumuPN[13];for(LhsxyuNz=0;Lhsx" ascii
    $s13 = "function fZPFlTT() {var kjBr=100000;var jXBUSZ = 100;return Math.random()*(kjBr-jXBUSZ)+jXBUSZ;}" fullword ascii
    $s14 = "function PVeOwXnXy(xjXwBcHoO,ErxoaUW,GcJkVVAk){" fullword ascii
    $s15 = "function JlVj(cokuMo,apbfqyF){cEcK = fAdRAXujiITirtuumuPN[11].split(fAdRAXujiITirtuumuPN[12]);apbfqyF.open(cEcK[0]+cEcK[2]+cEcK[" ascii
    $s16 = "function KoMYC(emSCizvn,lQhOye,ZLIFwjYnw){ZxQYv=emSCizvn.split(ZLIFwjYnw);AsVppLM = fAdRAXujiITirtuumuPN[13];for(LhsxyuNz=0;Lhsx" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}