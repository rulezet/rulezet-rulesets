rule TTP_XOR_QUAD_CurrentVersionRun_2944 {
  strings:
    $key_2944 = { 7a 2b [2] 5e 25 [2] 75 09 [2] 5b 2b [2] 4f 30 [2] 40 2a [2] 5e 37 [2] 5c 36 [2] 47 30 [2] 5b 37 [2] 47 18 }

  condition:
    any of them
}