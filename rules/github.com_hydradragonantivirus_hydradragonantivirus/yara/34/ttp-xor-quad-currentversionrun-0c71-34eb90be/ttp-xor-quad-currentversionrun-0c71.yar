rule TTP_XOR_QUAD_CurrentVersionRun_0c71 {
  strings:
    $key_0c71 = { 5f 1e [2] 7b 10 [2] 50 3c [2] 7e 1e [2] 6a 05 [2] 65 1f [2] 7b 02 [2] 79 03 [2] 62 05 [2] 7e 02 [2] 62 2d }

  condition:
    any of them
}