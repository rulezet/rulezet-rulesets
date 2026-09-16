rule TTP_XOR_QUAD_CurrentVersionRun_2965 {
  strings:
    $key_2965 = { 7a 0a [2] 5e 04 [2] 75 28 [2] 5b 0a [2] 4f 11 [2] 40 0b [2] 5e 16 [2] 5c 17 [2] 47 11 [2] 5b 16 [2] 47 39 }

  condition:
    any of them
}