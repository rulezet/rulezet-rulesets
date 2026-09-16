rule TTP_XOR_QUAD_CurrentVersionRun_0f52 {
  strings:
    $key_0f52 = { 5c 3d [2] 78 33 [2] 53 1f [2] 7d 3d [2] 69 26 [2] 66 3c [2] 78 21 [2] 7a 20 [2] 61 26 [2] 7d 21 [2] 61 0e }

  condition:
    any of them
}