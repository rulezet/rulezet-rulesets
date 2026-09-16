rule TTP_XOR_QUAD_CurrentVersionRun_1e05 {
  strings:
    $key_1e05 = { 4d 6a [2] 69 64 [2] 42 48 [2] 6c 6a [2] 78 71 [2] 77 6b [2] 69 76 [2] 6b 77 [2] 70 71 [2] 6c 76 [2] 70 59 }

  condition:
    any of them
}