rule TTP_XOR_QUAD_CurrentVersionRun_1871 {
  strings:
    $key_1871 = { 4b 1e [2] 6f 10 [2] 44 3c [2] 6a 1e [2] 7e 05 [2] 71 1f [2] 6f 02 [2] 6d 03 [2] 76 05 [2] 6a 02 [2] 76 2d }

  condition:
    any of them
}