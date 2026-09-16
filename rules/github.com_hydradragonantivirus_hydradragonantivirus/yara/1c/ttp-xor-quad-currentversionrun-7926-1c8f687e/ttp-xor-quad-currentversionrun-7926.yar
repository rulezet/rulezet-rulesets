rule TTP_XOR_QUAD_CurrentVersionRun_7926 {
  strings:
    $key_7926 = { 2a 49 [2] 0e 47 [2] 25 6b [2] 0b 49 [2] 1f 52 [2] 10 48 [2] 0e 55 [2] 0c 54 [2] 17 52 [2] 0b 55 [2] 17 7a }

  condition:
    any of them
}