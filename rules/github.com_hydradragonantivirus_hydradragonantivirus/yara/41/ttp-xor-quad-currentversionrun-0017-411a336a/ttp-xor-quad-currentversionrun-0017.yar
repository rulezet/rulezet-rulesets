rule TTP_XOR_QUAD_CurrentVersionRun_0017 {
  strings:
    $key_0017 = { 53 78 [2] 77 76 [2] 5c 5a [2] 72 78 [2] 66 63 [2] 69 79 [2] 77 64 [2] 75 65 [2] 6e 63 [2] 72 64 [2] 6e 4b }

  condition:
    any of them
}