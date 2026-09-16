rule TTP_XOR_QUAD_CurrentVersionRun_3264 {
  strings:
    $key_3264 = { 61 0b [2] 45 05 [2] 6e 29 [2] 40 0b [2] 54 10 [2] 5b 0a [2] 45 17 [2] 47 16 [2] 5c 10 [2] 40 17 [2] 5c 38 }

  condition:
    any of them
}