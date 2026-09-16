rule TTP_XOR_QUAD_CurrentVersionRun_c056 {
  strings:
    $key_c056 = { 93 39 [2] b7 37 [2] 9c 1b [2] b2 39 [2] a6 22 [2] a9 38 [2] b7 25 [2] b5 24 [2] ae 22 [2] b2 25 [2] ae 0a }

  condition:
    any of them
}