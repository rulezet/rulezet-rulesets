rule TTP_XOR_QUAD_CurrentVersionRun_21ca {
  strings:
    $key_21ca = { 72 a5 [2] 56 ab [2] 7d 87 [2] 53 a5 [2] 47 be [2] 48 a4 [2] 56 b9 [2] 54 b8 [2] 4f be [2] 53 b9 [2] 4f 96 }

  condition:
    any of them
}