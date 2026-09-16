rule TTP_XOR_QUAD_CurrentVersionRun_3544 {
  strings:
    $key_3544 = { 66 2b [2] 42 25 [2] 69 09 [2] 47 2b [2] 53 30 [2] 5c 2a [2] 42 37 [2] 40 36 [2] 5b 30 [2] 47 37 [2] 5b 18 }

  condition:
    any of them
}