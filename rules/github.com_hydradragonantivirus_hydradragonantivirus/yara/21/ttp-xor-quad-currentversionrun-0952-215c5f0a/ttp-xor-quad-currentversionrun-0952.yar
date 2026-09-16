rule TTP_XOR_QUAD_CurrentVersionRun_0952 {
  strings:
    $key_0952 = { 5a 3d [2] 7e 33 [2] 55 1f [2] 7b 3d [2] 6f 26 [2] 60 3c [2] 7e 21 [2] 7c 20 [2] 67 26 [2] 7b 21 [2] 67 0e }

  condition:
    any of them
}