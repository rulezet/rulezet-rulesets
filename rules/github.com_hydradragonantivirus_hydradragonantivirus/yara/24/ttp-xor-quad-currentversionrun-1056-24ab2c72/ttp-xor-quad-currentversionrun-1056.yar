rule TTP_XOR_QUAD_CurrentVersionRun_1056 {
  strings:
    $key_1056 = { 43 39 [2] 67 37 [2] 4c 1b [2] 62 39 [2] 76 22 [2] 79 38 [2] 67 25 [2] 65 24 [2] 7e 22 [2] 62 25 [2] 7e 0a }

  condition:
    any of them
}