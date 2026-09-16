rule TTP_XOR_QUAD_CurrentVersionRun_11ca {
  strings:
    $key_11ca = { 42 a5 [2] 66 ab [2] 4d 87 [2] 63 a5 [2] 77 be [2] 78 a4 [2] 66 b9 [2] 64 b8 [2] 7f be [2] 63 b9 [2] 7f 96 }

  condition:
    any of them
}