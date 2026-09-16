rule TTP_XOR_QUAD_CurrentVersionRun_4915 {
  strings:
    $key_4915 = { 1a 7a [2] 3e 74 [2] 15 58 [2] 3b 7a [2] 2f 61 [2] 20 7b [2] 3e 66 [2] 3c 67 [2] 27 61 [2] 3b 66 [2] 27 49 }

  condition:
    any of them
}