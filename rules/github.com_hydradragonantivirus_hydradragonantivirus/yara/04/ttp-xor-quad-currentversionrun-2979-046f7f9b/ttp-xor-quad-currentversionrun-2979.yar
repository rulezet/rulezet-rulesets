rule TTP_XOR_QUAD_CurrentVersionRun_2979 {
  strings:
    $key_2979 = { 7a 16 [2] 5e 18 [2] 75 34 [2] 5b 16 [2] 4f 0d [2] 40 17 [2] 5e 0a [2] 5c 0b [2] 47 0d [2] 5b 0a [2] 47 25 }

  condition:
    any of them
}