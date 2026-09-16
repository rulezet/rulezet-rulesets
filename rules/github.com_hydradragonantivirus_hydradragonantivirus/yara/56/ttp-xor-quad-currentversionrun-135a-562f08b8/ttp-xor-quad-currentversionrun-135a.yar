rule TTP_XOR_QUAD_CurrentVersionRun_135a {
  strings:
    $key_135a = { 40 35 [2] 64 3b [2] 4f 17 [2] 61 35 [2] 75 2e [2] 7a 34 [2] 64 29 [2] 66 28 [2] 7d 2e [2] 61 29 [2] 7d 06 }

  condition:
    any of them
}