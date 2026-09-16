rule TTP_XOR_QUAD_CurrentVersionRun_4fff {
  strings:
    $key_4fff = { 1c 90 [2] 38 9e [2] 13 b2 [2] 3d 90 [2] 29 8b [2] 26 91 [2] 38 8c [2] 3a 8d [2] 21 8b [2] 3d 8c [2] 21 a3 }

  condition:
    any of them
}