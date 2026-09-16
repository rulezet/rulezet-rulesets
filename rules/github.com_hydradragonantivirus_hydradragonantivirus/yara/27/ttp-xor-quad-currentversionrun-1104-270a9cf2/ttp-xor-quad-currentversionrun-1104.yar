rule TTP_XOR_QUAD_CurrentVersionRun_1104 {
  strings:
    $key_1104 = { 42 6b [2] 66 65 [2] 4d 49 [2] 63 6b [2] 77 70 [2] 78 6a [2] 66 77 [2] 64 76 [2] 7f 70 [2] 63 77 [2] 7f 58 }

  condition:
    any of them
}