rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_6f40563df6af_4510 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash3       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash4       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"
    hash5       = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"

  strings:
    $s1 = "})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000" ascii
    $s2 = "GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";})(),(functi" ascii
    $s3 = "(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";}" ascii
    $s4 = "ction f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return" ascii
    $s5 = "urn \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}