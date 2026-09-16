rule TTP_XOR_QUAD_CurrentVersionRun_4c71 {
  strings:
    $key_4c71 = { 1f 1e [2] 3b 10 [2] 10 3c [2] 3e 1e [2] 2a 05 [2] 25 1f [2] 3b 02 [2] 39 03 [2] 22 05 [2] 3e 02 [2] 22 2d }

  condition:
    any of them
}