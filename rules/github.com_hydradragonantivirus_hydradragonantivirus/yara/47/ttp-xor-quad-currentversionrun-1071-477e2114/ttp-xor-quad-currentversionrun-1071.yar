rule TTP_XOR_QUAD_CurrentVersionRun_1071 {
  strings:
    $key_1071 = { 43 1e [2] 67 10 [2] 4c 3c [2] 62 1e [2] 76 05 [2] 79 1f [2] 67 02 [2] 65 03 [2] 7e 05 [2] 62 02 [2] 7e 2d }

  condition:
    any of them
}