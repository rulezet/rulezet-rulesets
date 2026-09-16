rule TTP_XOR_QUAD_CurrentVersionRun_6b56 {
  strings:
    $key_6b56 = { 38 39 [2] 1c 37 [2] 37 1b [2] 19 39 [2] 0d 22 [2] 02 38 [2] 1c 25 [2] 1e 24 [2] 05 22 [2] 19 25 [2] 05 0a }

  condition:
    any of them
}