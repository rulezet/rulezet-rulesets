rule TTP_XOR_QUAD_CurrentVersionRun_2852 {
  strings:
    $key_2852 = { 7b 3d [2] 5f 33 [2] 74 1f [2] 5a 3d [2] 4e 26 [2] 41 3c [2] 5f 21 [2] 5d 20 [2] 46 26 [2] 5a 21 [2] 46 0e }

  condition:
    any of them
}