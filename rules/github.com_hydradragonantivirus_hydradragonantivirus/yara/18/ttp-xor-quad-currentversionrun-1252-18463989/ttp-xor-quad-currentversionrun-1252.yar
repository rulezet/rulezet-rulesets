rule TTP_XOR_QUAD_CurrentVersionRun_1252 {
  strings:
    $key_1252 = { 41 3d [2] 65 33 [2] 4e 1f [2] 60 3d [2] 74 26 [2] 7b 3c [2] 65 21 [2] 67 20 [2] 7c 26 [2] 60 21 [2] 7c 0e }

  condition:
    any of them
}