rule _20160921_1b24f7151bebd3644ff0608076bd2de9_20160921_4fa304d7c11d_1672 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js, 20160921_91af5c220d1ea27d72d05f472ba8fa16.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js, 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js, 20160921_b74bfd3dc7404d3d5a6512718aa52504.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash2       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash3       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"
    hash4       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"
    hash5       = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"
    hash6       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"
    hash7       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"
    hash8       = "359d333ab8fc51d27349ecaec71f8baf8e8aafae5bfe2d6afd26f4ed76e802db"
    hash9       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1  = "nction fuck(){return \"Xw\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"To\";})(),(function fuck(){retur" ascii
    $s2  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"" ascii
    $s3  = "),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s4  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){" ascii
    $s5  = "ck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xw\";}" ascii
    $s6  = ";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Ai\";})(),(function fu" ascii
    $s7  = "ck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Ai\";" ascii
    $s8  = "tion fuck(){return \"Wo\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s9  = "urn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(f" ascii
    $s10 = "){return \"XHj\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"VMi\";}" ascii
    $s11 = "ion fuck(){return \"Jg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}