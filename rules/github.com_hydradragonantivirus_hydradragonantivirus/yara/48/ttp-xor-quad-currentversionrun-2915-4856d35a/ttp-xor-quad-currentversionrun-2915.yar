rule TTP_XOR_QUAD_CurrentVersionRun_2915 {
  strings:
    $key_2915 = { 7a 7a [2] 5e 74 [2] 75 58 [2] 5b 7a [2] 4f 61 [2] 40 7b [2] 5e 66 [2] 5c 67 [2] 47 61 [2] 5b 66 [2] 47 49 }

  condition:
    any of them
}