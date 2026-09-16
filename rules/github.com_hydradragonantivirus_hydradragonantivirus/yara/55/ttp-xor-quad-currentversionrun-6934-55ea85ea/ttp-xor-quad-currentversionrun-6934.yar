rule TTP_XOR_QUAD_CurrentVersionRun_6934 {
  strings:
    $key_6934 = { 3a 5b [2] 1e 55 [2] 35 79 [2] 1b 5b [2] 0f 40 [2] 00 5a [2] 1e 47 [2] 1c 46 [2] 07 40 [2] 1b 47 [2] 07 68 }

  condition:
    any of them
}