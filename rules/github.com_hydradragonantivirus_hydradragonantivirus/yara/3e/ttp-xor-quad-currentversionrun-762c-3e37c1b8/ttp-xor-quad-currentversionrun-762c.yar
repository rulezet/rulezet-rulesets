rule TTP_XOR_QUAD_CurrentVersionRun_762c {
  strings:
    $key_762c = { 25 43 [2] 01 4d [2] 2a 61 [2] 04 43 [2] 10 58 [2] 1f 42 [2] 01 5f [2] 03 5e [2] 18 58 [2] 04 5f [2] 18 70 }

  condition:
    any of them
}