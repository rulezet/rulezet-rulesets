rule TTP_XOR_QUAD_CurrentVersionRun_6c27 {
  strings:
    $key_6c27 = { 3f 48 [2] 1b 46 [2] 30 6a [2] 1e 48 [2] 0a 53 [2] 05 49 [2] 1b 54 [2] 19 55 [2] 02 53 [2] 1e 54 [2] 02 7b }

  condition:
    any of them
}