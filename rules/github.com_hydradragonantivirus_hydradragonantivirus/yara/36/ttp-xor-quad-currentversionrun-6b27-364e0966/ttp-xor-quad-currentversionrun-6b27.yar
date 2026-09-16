rule TTP_XOR_QUAD_CurrentVersionRun_6b27 {
  strings:
    $key_6b27 = { 38 48 [2] 1c 46 [2] 37 6a [2] 19 48 [2] 0d 53 [2] 02 49 [2] 1c 54 [2] 1e 55 [2] 05 53 [2] 19 54 [2] 05 7b }

  condition:
    any of them
}