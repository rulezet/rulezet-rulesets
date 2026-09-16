rule TTP_XOR_QUAD_CurrentVersionRun_7a4f {
  strings:
    $key_7a4f = { 29 20 [2] 0d 2e [2] 26 02 [2] 08 20 [2] 1c 3b [2] 13 21 [2] 0d 3c [2] 0f 3d [2] 14 3b [2] 08 3c [2] 14 13 }

  condition:
    any of them
}