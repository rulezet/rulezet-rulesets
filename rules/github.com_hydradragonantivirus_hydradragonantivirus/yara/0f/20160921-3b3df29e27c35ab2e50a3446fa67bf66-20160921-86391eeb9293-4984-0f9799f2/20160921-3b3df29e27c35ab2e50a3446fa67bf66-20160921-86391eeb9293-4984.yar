rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_86391eeb9293_4984 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash3       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash4       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"

  strings:
    $s1 = "unction f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s2 = "n\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s3 = "eturn \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"QDg\";})()" ascii
    $s4 = "n \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(fun" ascii
    $s5 = "00(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}