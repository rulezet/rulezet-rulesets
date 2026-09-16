rule TTP_XOR_QUAD_CurrentVersionRun_162b {
  strings:
    $key_162b = { 45 44 [2] 61 4a [2] 4a 66 [2] 64 44 [2] 70 5f [2] 7f 45 [2] 61 58 [2] 63 59 [2] 78 5f [2] 64 58 [2] 78 77 }

  condition:
    any of them
}