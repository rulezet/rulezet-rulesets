rule TTP_XOR_QUAD_CurrentVersionRun_4935 {
  strings:
    $key_4935 = { 1a 5a [2] 3e 54 [2] 15 78 [2] 3b 5a [2] 2f 41 [2] 20 5b [2] 3e 46 [2] 3c 47 [2] 27 41 [2] 3b 46 [2] 27 69 }

  condition:
    any of them
}