rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_1363f95b1c66_379 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash3       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash4       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"
    hash5       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"
    hash6       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1  = "})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"RAi\";})(),(function fu" ascii
    $s2  = "(){return \"IOs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s3  = "u\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s4  = "tion fuck(){return \"Xw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s5  = "{return \"DWe\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s6  = "return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})()," ascii
    $s7  = "){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Cd\";}" ascii
    $s8  = "ck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IOs\"" ascii
    $s9  = "ck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZWu" ascii
    $s10 = "return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"FJs\";})(" ascii
    $s11 = "urn \"Fv\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s12 = "function fuck(){return \"XFd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){re" ascii
    $s13 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Av\";})(),(function fuck(){ret" ascii
    $s14 = "n \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Jg\";})(),(funct" ascii
    $s15 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retu" ascii
    $s16 = "\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IOs\";})(),(function f" ascii
    $s17 = "})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck" ascii
    $s18 = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ar\";" ascii
    $s19 = "(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"LLv\";})(),(function fuck()" ascii
    $s20 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Wo\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}