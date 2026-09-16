rule TTP_XOR_QUAD_CurrentVersionRun_6b34 {
  strings:
    $key_6b34 = { 38 5b [2] 1c 55 [2] 37 79 [2] 19 5b [2] 0d 40 [2] 02 5a [2] 1c 47 [2] 1e 46 [2] 05 40 [2] 19 47 [2] 05 68 }

  condition:
    any of them
}