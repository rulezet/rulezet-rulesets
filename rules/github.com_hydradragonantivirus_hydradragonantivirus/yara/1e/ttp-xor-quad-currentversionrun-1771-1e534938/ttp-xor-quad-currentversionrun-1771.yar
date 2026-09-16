rule TTP_XOR_QUAD_CurrentVersionRun_1771 {
  strings:
    $key_1771 = { 44 1e [2] 60 10 [2] 4b 3c [2] 65 1e [2] 71 05 [2] 7e 1f [2] 60 02 [2] 62 03 [2] 79 05 [2] 65 02 [2] 79 2d }

  condition:
    any of them
}