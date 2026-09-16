rule TTP_XOR_QUAD_CurrentVersionRun_2952 {
  strings:
    $key_2952 = { 7a 3d [2] 5e 33 [2] 75 1f [2] 5b 3d [2] 4f 26 [2] 40 3c [2] 5e 21 [2] 5c 20 [2] 47 26 [2] 5b 21 [2] 47 0e }

  condition:
    any of them
}