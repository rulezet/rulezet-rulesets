rule sig_20160526_4f2d8ca2de5e94f3258bcd48b99295b4 {
  meta:
    description = "datamaliciousorder - file 20160526_4f2d8ca2de5e94f3258bcd48b99295b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80ab400bd310771d6955d0addc7c493f5e5acbfa43461a478eb346367f45da22"

  strings:
    $s1  = "Math.pow(Math.sin(977), 2) + Math.pow(Math.cos(977), 2) - 1))-181) | vhWKkkWQInBkyGSqQnLJrZS<< (301 + Math.round((Math.pow(Math." ascii
    $s2  = "== (386 + Math.round((Math.pow(Math.sin(145), 2) + Math.pow(Math.cos(145), 2) - 1))-322)) fKXzqotRpDYjf += Fg(ngcqsduxTa);else i" ascii
    $s3  = "function OKZgL(LxmStrdjsyFkc) {var axoBKlrPj = YVBmUfFAFNLDNE.join(fJbjdAzBfupbXDIv[0]);var ngcqsduxTa, raHHoQAbboOUaPTCdMyAHfq," ascii
    $s4  = "function VGVTsu(duTOZgLUeX,qAiKylVPoiURMN){return duTOZgLUeX.charAt(qAiKylVPoiURMN);}" fullword ascii
    $s5  = "function OKZgL(LxmStrdjsyFkc) {var axoBKlrPj = YVBmUfFAFNLDNE.join(fJbjdAzBfupbXDIv[0]);var ngcqsduxTa, raHHoQAbboOUaPTCdMyAHfq," ascii
    $s6  = "function Fg(FgdfjgeZuwHRMqvSrP){return String.fromCharCode(FgdfjgeZuwHRMqvSrP);}" fullword ascii
    $s7  = "iHFglz < LxmStrdjsyFkc.length);return fKXzqotRpDYjf;}" fullword ascii
    $s8  = "gcqsduxTa, raHHoQAbboOUaPTCdMyAHfq);else fKXzqotRpDYjf += MdWPoge(ngcqsduxTa, raHHoQAbboOUaPTCdMyAHfq, ruLfRBn);} while (yJuCODK" ascii
    $s9  = "function MdWPoge(EtTwePviucCv,uRHKP,huWzr){return String.fromCharCode(EtTwePviucCv,uRHKP,huWzr);}" fullword ascii
    $s10 = "function TDIrEzcHKX(vxMcYUP,ykPplqwAIlikd){return vxMcYUP.indexOf(ykPplqwAIlikd);}" fullword ascii
    $s11 = "function GasRuPh(rdScLKYUDYvljyCk,jUHvVbtzdYikSAp){return String.fromCharCode(rdScLKYUDYvljyCk,jUHvVbtzdYikSAp);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}