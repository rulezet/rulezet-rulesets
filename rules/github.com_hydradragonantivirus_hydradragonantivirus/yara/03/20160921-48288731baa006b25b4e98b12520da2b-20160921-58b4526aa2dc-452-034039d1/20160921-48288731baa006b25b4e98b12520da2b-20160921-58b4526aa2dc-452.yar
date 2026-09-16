rule _20160921_48288731baa006b25b4e98b12520da2b_20160921_58b4526aa2dc_452 {
  meta:
    description = "datamaliciousorder - from files 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash2       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash3       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash4       = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"

  strings:
    $s1  = "uck(){return \"Ot\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu" ascii
    $s2  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retur" ascii
    $s3  = "),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XCr\";})(),(function fuck(" ascii
    $s4  = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"" ascii
    $s5  = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"FJs\";})(" ascii
    $s6  = "urn \"Cd\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s7  = "on fuck(){return \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s8  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return " ascii
    $s9  = "(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})" ascii
    $s10 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"DAa\";})(),(function" ascii
    $s11 = "return \"Dc\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(" ascii
    $s12 = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"EHo\";})(),(fu" ascii
    $s13 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"" ascii
    $s14 = " \"GJx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"To\";})(),(fun" ascii
    $s15 = "Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ot\";})(),(function" ascii
    $s16 = "ction fuck(){return \"Xg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return" ascii
    $s17 = "fuck(){return \"Oh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xw" ascii
    $s18 = "n \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(func" ascii
    $s19 = "n \"Xw\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s20 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"A" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}