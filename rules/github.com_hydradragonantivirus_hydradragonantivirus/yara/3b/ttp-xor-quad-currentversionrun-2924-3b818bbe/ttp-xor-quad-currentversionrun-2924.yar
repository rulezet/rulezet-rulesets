rule TTP_XOR_QUAD_CurrentVersionRun_2924 {
  strings:
    $key_2924 = { 7a 4b [2] 5e 45 [2] 75 69 [2] 5b 4b [2] 4f 50 [2] 40 4a [2] 5e 57 [2] 5c 56 [2] 47 50 [2] 5b 57 [2] 47 78 }

  condition:
    any of them
}