rule TTP_XOR_QUAD_CurrentVersionRun_0b3d {
  strings:
    $key_0b3d = { 58 52 [2] 7c 5c [2] 57 70 [2] 79 52 [2] 6d 49 [2] 62 53 [2] 7c 4e [2] 7e 4f [2] 65 49 [2] 79 4e [2] 65 61 }

  condition:
    any of them
}