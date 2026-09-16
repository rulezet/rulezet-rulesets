rule TTP_XOR_QUAD_CurrentVersionRun_3517 {
  strings:
    $key_3517 = { 66 78 [2] 42 76 [2] 69 5a [2] 47 78 [2] 53 63 [2] 5c 79 [2] 42 64 [2] 40 65 [2] 5b 63 [2] 47 64 [2] 5b 4b }

  condition:
    any of them
}