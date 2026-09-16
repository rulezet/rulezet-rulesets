rule TTP_XOR_QUAD_CurrentVersionRun_2b4b {
  strings:
    $key_2b4b = { 78 24 [2] 5c 2a [2] 77 06 [2] 59 24 [2] 4d 3f [2] 42 25 [2] 5c 38 [2] 5e 39 [2] 45 3f [2] 59 38 [2] 45 17 }

  condition:
    any of them
}