rule TTP_XOR_QUAD_CurrentVersionRun_0152 {
  strings:
    $key_0152 = { 52 3d [2] 76 33 [2] 5d 1f [2] 73 3d [2] 67 26 [2] 68 3c [2] 76 21 [2] 74 20 [2] 6f 26 [2] 73 21 [2] 6f 0e }

  condition:
    any of them
}