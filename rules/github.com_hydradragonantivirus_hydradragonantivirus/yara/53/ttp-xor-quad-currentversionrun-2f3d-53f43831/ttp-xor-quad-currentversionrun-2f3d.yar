rule TTP_XOR_QUAD_CurrentVersionRun_2f3d {
  strings:
    $key_2f3d = { 7c 52 [2] 58 5c [2] 73 70 [2] 5d 52 [2] 49 49 [2] 46 53 [2] 58 4e [2] 5a 4f [2] 41 49 [2] 5d 4e [2] 41 61 }

  condition:
    any of them
}