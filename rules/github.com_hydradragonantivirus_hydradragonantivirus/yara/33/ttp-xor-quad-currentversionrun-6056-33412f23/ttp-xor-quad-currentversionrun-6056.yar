rule TTP_XOR_QUAD_CurrentVersionRun_6056 {
  strings:
    $key_6056 = { 33 39 [2] 17 37 [2] 3c 1b [2] 12 39 [2] 06 22 [2] 09 38 [2] 17 25 [2] 15 24 [2] 0e 22 [2] 12 25 [2] 0e 0a }

  condition:
    any of them
}