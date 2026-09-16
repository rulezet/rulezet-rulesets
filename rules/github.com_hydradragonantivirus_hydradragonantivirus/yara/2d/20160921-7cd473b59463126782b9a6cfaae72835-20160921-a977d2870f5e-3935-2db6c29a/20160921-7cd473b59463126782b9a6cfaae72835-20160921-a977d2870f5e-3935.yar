rule _20160921_7cd473b59463126782b9a6cfaae72835_20160921_a977d2870f5e_3935 {
  meta:
    description = "datamaliciousorder - from files 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash2       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash3       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1 = "h\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function " ascii
    $s2 = ";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f0" ascii
    $s3 = "tion f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s4 = "tion f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s5 = "\"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Tn\";})(),(funct" ascii
    $s6 = "unction f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}