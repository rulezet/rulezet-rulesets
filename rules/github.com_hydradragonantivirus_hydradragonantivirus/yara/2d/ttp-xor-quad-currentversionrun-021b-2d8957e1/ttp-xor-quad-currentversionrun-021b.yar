rule TTP_XOR_QUAD_CurrentVersionRun_021b {
  strings:
    $key_021b = { 51 74 [2] 75 7a [2] 5e 56 [2] 70 74 [2] 64 6f [2] 6b 75 [2] 75 68 [2] 77 69 [2] 6c 6f [2] 70 68 [2] 6c 47 }

  condition:
    any of them
}