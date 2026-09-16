rule TTP_XOR_QUAD_CurrentVersionRun_3554 {
  strings:
    $key_3554 = { 66 3b [2] 42 35 [2] 69 19 [2] 47 3b [2] 53 20 [2] 5c 3a [2] 42 27 [2] 40 26 [2] 5b 20 [2] 47 27 [2] 5b 08 }

  condition:
    any of them
}