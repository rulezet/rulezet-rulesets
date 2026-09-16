rule TTP_XOR_QUAD_CurrentVersionRun_3c52 {
  strings:
    $key_3c52 = { 6f 3d [2] 4b 33 [2] 60 1f [2] 4e 3d [2] 5a 26 [2] 55 3c [2] 4b 21 [2] 49 20 [2] 52 26 [2] 4e 21 [2] 52 0e }

  condition:
    any of them
}