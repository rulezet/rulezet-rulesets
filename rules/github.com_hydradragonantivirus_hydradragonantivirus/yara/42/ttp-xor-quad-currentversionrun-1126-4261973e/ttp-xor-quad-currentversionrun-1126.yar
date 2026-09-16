rule TTP_XOR_QUAD_CurrentVersionRun_1126 {
  strings:
    $key_1126 = { 42 49 [2] 66 47 [2] 4d 6b [2] 63 49 [2] 77 52 [2] 78 48 [2] 66 55 [2] 64 54 [2] 7f 52 [2] 63 55 [2] 7f 7a }

  condition:
    any of them
}