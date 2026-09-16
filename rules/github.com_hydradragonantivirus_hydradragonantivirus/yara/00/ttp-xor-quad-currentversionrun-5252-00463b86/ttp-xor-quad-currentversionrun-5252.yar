rule TTP_XOR_QUAD_CurrentVersionRun_5252 {
  strings:
    $key_5252 = { 01 3d [2] 25 33 [2] 0e 1f [2] 20 3d [2] 34 26 [2] 3b 3c [2] 25 21 [2] 27 20 [2] 3c 26 [2] 20 21 [2] 3c 0e }

  condition:
    any of them
}