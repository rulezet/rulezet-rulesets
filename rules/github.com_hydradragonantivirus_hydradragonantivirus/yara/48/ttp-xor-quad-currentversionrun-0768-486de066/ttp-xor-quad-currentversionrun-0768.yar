rule TTP_XOR_QUAD_CurrentVersionRun_0768 {
  strings:
    $key_0768 = { 54 07 [2] 70 09 [2] 5b 25 [2] 75 07 [2] 61 1c [2] 6e 06 [2] 70 1b [2] 72 1a [2] 69 1c [2] 75 1b [2] 69 34 }

  condition:
    any of them
}