rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_60c26fdfafa2_3203 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_60c26fdfafa2666b92246aea46e32175.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"

  strings:
    $s1 = " \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(func" ascii
    $s2 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZIi\";})(),(function f00" ascii
    $s3 = "nction f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){retur" ascii
    $s4 = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZFe\";})(),(func" ascii
    $s5 = "0(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sj\";" ascii
    $s6 = "n f000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"G" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}