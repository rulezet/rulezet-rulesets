rule TTP_XOR_QUAD_CurrentVersionRun_3245 {
  strings:
    $key_3245 = { 61 2a [2] 45 24 [2] 6e 08 [2] 40 2a [2] 54 31 [2] 5b 2b [2] 45 36 [2] 47 37 [2] 5c 31 [2] 40 36 [2] 5c 19 }

  condition:
    any of them
}