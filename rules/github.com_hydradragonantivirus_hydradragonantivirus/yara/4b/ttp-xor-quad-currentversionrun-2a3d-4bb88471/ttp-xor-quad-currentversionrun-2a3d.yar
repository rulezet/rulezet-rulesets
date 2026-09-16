rule TTP_XOR_QUAD_CurrentVersionRun_2a3d {
  strings:
    $key_2a3d = { 79 52 [2] 5d 5c [2] 76 70 [2] 58 52 [2] 4c 49 [2] 43 53 [2] 5d 4e [2] 5f 4f [2] 44 49 [2] 58 4e [2] 44 61 }

  condition:
    any of them
}