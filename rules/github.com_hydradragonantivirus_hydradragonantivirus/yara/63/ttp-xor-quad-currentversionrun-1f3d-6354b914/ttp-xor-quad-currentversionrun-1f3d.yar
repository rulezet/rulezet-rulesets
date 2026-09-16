rule TTP_XOR_QUAD_CurrentVersionRun_1f3d {
  strings:
    $key_1f3d = { 4c 52 [2] 68 5c [2] 43 70 [2] 6d 52 [2] 79 49 [2] 76 53 [2] 68 4e [2] 6a 4f [2] 71 49 [2] 6d 4e [2] 71 61 }

  condition:
    any of them
}