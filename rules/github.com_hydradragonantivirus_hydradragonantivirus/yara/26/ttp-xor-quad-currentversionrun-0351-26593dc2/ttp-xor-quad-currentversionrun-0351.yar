rule TTP_XOR_QUAD_CurrentVersionRun_0351 {
  strings:
    $key_0351 = { 50 3e [2] 74 30 [2] 5f 1c [2] 71 3e [2] 65 25 [2] 6a 3f [2] 74 22 [2] 76 23 [2] 6d 25 [2] 71 22 [2] 6d 0d }

  condition:
    any of them
}