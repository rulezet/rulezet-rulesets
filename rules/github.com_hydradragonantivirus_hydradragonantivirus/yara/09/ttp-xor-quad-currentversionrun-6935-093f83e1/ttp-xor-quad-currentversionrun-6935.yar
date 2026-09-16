rule TTP_XOR_QUAD_CurrentVersionRun_6935 {
  strings:
    $key_6935 = { 3a 5a [2] 1e 54 [2] 35 78 [2] 1b 5a [2] 0f 41 [2] 00 5b [2] 1e 46 [2] 1c 47 [2] 07 41 [2] 1b 46 [2] 07 69 }

  condition:
    any of them
}