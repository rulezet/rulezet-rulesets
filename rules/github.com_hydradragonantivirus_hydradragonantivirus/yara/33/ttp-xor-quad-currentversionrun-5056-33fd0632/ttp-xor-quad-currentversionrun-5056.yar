rule TTP_XOR_QUAD_CurrentVersionRun_5056 {
  strings:
    $key_5056 = { 03 39 [2] 27 37 [2] 0c 1b [2] 22 39 [2] 36 22 [2] 39 38 [2] 27 25 [2] 25 24 [2] 3e 22 [2] 22 25 [2] 3e 0a }

  condition:
    any of them
}