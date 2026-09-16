rule TTP_XOR_QUAD_CurrentVersionRun_495b {
  strings:
    $key_495b = { 1a 34 [2] 3e 3a [2] 15 16 [2] 3b 34 [2] 2f 2f [2] 20 35 [2] 3e 28 [2] 3c 29 [2] 27 2f [2] 3b 28 [2] 27 07 }

  condition:
    any of them
}