rule TTP_XOR_QUAD_CurrentVersionRun_0056 {
  strings:
    $key_0056 = { 53 39 [2] 77 37 [2] 5c 1b [2] 72 39 [2] 66 22 [2] 69 38 [2] 77 25 [2] 75 24 [2] 6e 22 [2] 72 25 [2] 6e 0a }

  condition:
    any of them
}