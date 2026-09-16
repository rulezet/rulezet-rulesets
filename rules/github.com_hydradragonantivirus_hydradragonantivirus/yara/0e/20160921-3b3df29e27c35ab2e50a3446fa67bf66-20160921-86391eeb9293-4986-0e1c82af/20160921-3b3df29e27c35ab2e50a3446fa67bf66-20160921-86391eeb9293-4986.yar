rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_86391eeb9293_4986 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash3       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash4       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = "n \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(func" ascii
    $s2 = "0(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s3 = ")(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f00" ascii
    $s4 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})" ascii
    $s5 = "tion f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}