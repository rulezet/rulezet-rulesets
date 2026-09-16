rule sig_20151217_829ee3ce69f42c1d0d06dbfd3f8288b9 {
  meta:
    description = "datamaliciousorder - file 20151217_829ee3ce69f42c1d0d06dbfd3f8288b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "792b409d069ffde444df15c57bc36ef742b23f9e928b3f508e7c6b477d3c90de"

  strings:
    $s1  = "function eZzCvqDVZbzDEFhkt(tdmGh){YAcuBtxmbFp= '';TcdFtbclrYu=Math.round((Math.pow(Math.sin(773), 2) + Math.pow(Math.cos(773), 2" ascii
    $s2  = "ow(Math.cos(721), 2) - 1)));} jlkvkJJkj[TcdFtbclrYu]++;}TcdFtbclrYu++;} return YAcuBtxmbFp}" fullword ascii
    $s3  = "th.pow(Math.cos(584), 2) - 1)); while(true) { if(jlkvkJJkj[TcdFtbclrYu] > tdmGh[TcdFtbclrYu].length-(173+193)/366) { break; } if" ascii
    $s4  = ") - 1));while(true){if (TcdFtbclrYu >= (2169+963)/522){break;}jlkvkJJkj[TcdFtbclrYu]=Math.round((Math.pow(Math.sin(584), 2) + Ma" ascii
    $s5  = "function eZzCvqDVZbzDEFhkt(tdmGh){YAcuBtxmbFp= '';TcdFtbclrYu=Math.round((Math.pow(Math.sin(773), 2) + Math.pow(Math.cos(773), 2" ascii
    $s6  = "function sehuJLd(FEvBakowLHslJuIfjsEPFyQVTfcyiedmYOTd) {return !VaSmwOtjDCD(TtfsBPBqPgxQvYy(FEvBakowLHslJuIfjsEPFyQVTfcyiedmYOTd" ascii
    $s7  = "var k = new Array();k[0]=[];k[0][0]='d';k[0][1]='a';k[0][2]='d';k[0][3]='a';k[0][4]='46';k[0][5]='3d';k[0][6]='42';k[0][7]='14';" ascii
    $s8  = "function Z(XZLQrjKhfomO,UzNUyRzCewVFcj){XZLQrjKhfomO.push(UzNUyRzCewVFcj);}" fullword ascii
    $s9  = "function mzpJZ(SRkdhKilfrO,YMZTNpCLHaVgV,PQISIsRa){KhMq=EnOMgKliSoUbfWuYI(SRkdhKilfrO,YMZTNpCLHaVgV);ueZfv=KhMq.toString(PQISIsR" ascii
    $s10 = "function VaSmwOtjDCD(IKghNHheiSXurt) {return isNaN(IKghNHheiSXurt);}" fullword ascii
    $s11 = "function HkSaqaszajeCiOK(exUMANsaHpsxzyxRX,HRkrjNtNSEXnVDuvfcpciUYPGPKIEhIQkD,yggABfTlovUJlupwKKijhceTUfwvmaQUdKI){eval(exUMANsa" ascii
    $s12 = "function EnOMgKliSoUbfWuYI(dNgPzEiqgR,TtRmgxcmGu) {return parseInt(dNgPzEiqgR,TtRmgxcmGu);}" fullword ascii
    $s13 = "function HkSaqaszajeCiOK(exUMANsaHpsxzyxRX,HRkrjNtNSEXnVDuvfcpciUYPGPKIEhIQkD,yggABfTlovUJlupwKKijhceTUfwvmaQUdKI){eval(exUMANsa" ascii
    $s14 = "function YITsFayCWOrPDjZyeKpYEuQjieoNibKjyzXAubGrsRovaoXxceYZAm(hlOZPbMPEBppu,jeUpepYCoLxWDt){ return WbHzQcy[SgbxqexS[mzpJZ(hlO" ascii
    $s15 = "function DmThTsiscJVu(xASZdTqTKvaaw) {return isFinite(xASZdTqTKvaaw);}" fullword ascii
    $s16 = "function sehuJLd(FEvBakowLHslJuIfjsEPFyQVTfcyiedmYOTd) {return !VaSmwOtjDCD(TtfsBPBqPgxQvYy(FEvBakowLHslJuIfjsEPFyQVTfcyiedmYOTd" ascii
    $s17 = "function mzpJZ(SRkdhKilfrO,YMZTNpCLHaVgV,PQISIsRa){KhMq=EnOMgKliSoUbfWuYI(SRkdhKilfrO,YMZTNpCLHaVgV);ueZfv=KhMq.toString(PQISIsR" ascii
    $s18 = "var k = new Array();k[0]=[];k[0][0]='d';k[0][1]='a';k[0][2]='d';k[0][3]='a';k[0][4]='46';k[0][5]='3d';k[0][6]='42';k[0][7]='14';" ascii
    $s19 = "function TtfsBPBqPgxQvYy(iiOXDUDVIqaLvkxEPtU) {return parseFloat(iiOXDUDVIqaLvkxEPtU);}" fullword ascii
    $s20 = "a);return ueZfv;}" fullword ascii

  condition:
    uint16(0) == 0x6753 and
    8 of them
}