rule TTP_XOR_QUAD_CurrentVersionRun_3546 {
  strings:
    $key_3546 = { 66 29 [2] 42 27 [2] 69 0b [2] 47 29 [2] 53 32 [2] 5c 28 [2] 42 35 [2] 40 34 [2] 5b 32 [2] 47 35 [2] 5b 1a }

  condition:
    any of them
}