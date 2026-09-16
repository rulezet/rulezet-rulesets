rule TTP_XOR_QUAD_CurrentVersionRun_484a {
  strings:
    $key_484a = { 1b 25 [2] 3f 2b [2] 14 07 [2] 3a 25 [2] 2e 3e [2] 21 24 [2] 3f 39 [2] 3d 38 [2] 26 3e [2] 3a 39 [2] 26 16 }

  condition:
    any of them
}