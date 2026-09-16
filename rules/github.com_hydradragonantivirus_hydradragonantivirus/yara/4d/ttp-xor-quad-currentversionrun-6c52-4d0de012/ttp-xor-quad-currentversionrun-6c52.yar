rule TTP_XOR_QUAD_CurrentVersionRun_6c52 {
  strings:
    $key_6c52 = { 3f 3d [2] 1b 33 [2] 30 1f [2] 1e 3d [2] 0a 26 [2] 05 3c [2] 1b 21 [2] 19 20 [2] 02 26 [2] 1e 21 [2] 02 0e }

  condition:
    any of them
}