rule TTP_XOR_QUAD_CurrentVersionRun_2d29 {
  strings:
    $key_2d29 = { 7e 46 [2] 5a 48 [2] 71 64 [2] 5f 46 [2] 4b 5d [2] 44 47 [2] 5a 5a [2] 58 5b [2] 43 5d [2] 5f 5a [2] 43 75 }

  condition:
    any of them
}