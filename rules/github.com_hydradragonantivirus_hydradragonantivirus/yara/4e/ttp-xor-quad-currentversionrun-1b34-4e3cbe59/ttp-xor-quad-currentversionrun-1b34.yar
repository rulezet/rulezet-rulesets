rule TTP_XOR_QUAD_CurrentVersionRun_1b34 {
  strings:
    $key_1b34 = { 48 5b [2] 6c 55 [2] 47 79 [2] 69 5b [2] 7d 40 [2] 72 5a [2] 6c 47 [2] 6e 46 [2] 75 40 [2] 69 47 [2] 75 68 }

  condition:
    any of them
}