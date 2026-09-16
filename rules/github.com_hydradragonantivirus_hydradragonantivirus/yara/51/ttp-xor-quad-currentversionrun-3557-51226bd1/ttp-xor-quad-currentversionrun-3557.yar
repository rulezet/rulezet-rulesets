rule TTP_XOR_QUAD_CurrentVersionRun_3557 {
  strings:
    $key_3557 = { 66 38 [2] 42 36 [2] 69 1a [2] 47 38 [2] 53 23 [2] 5c 39 [2] 42 24 [2] 40 25 [2] 5b 23 [2] 47 24 [2] 5b 0b }

  condition:
    any of them
}