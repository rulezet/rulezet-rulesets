rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_2746dcb02909_4701 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash3       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash4       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1 = "n f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Z" ascii
    $s2 = "nction f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){ret" ascii
    $s3 = "return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})()," ascii
    $s4 = "o\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s5 = "return \"Wh\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}