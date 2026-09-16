rule _20160921_02b826231ece268e91633311d2c70554_20160921_f3a36d70a836_3181 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = "000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qa\"" ascii
    $s2 = "(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";}" ascii
    $s3 = "000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe" ascii
    $s4 = "000(){return \"Oh\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qa\"" ascii
    $s5 = "turn \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})()," ascii
    $s6 = "function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KDh\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}