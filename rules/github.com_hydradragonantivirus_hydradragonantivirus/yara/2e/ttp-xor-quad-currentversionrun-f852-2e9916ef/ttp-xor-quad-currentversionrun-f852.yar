rule TTP_XOR_QUAD_CurrentVersionRun_f852 {
  strings:
    $key_f852 = { ab 3d [2] 8f 33 [2] a4 1f [2] 8a 3d [2] 9e 26 [2] 91 3c [2] 8f 21 [2] 8d 20 [2] 96 26 [2] 8a 21 [2] 96 0e }

  condition:
    any of them
}