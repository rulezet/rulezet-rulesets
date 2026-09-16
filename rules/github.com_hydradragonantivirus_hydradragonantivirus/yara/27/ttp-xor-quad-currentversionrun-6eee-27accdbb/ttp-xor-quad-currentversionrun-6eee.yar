rule TTP_XOR_QUAD_CurrentVersionRun_6eee {
  strings:
    $key_6eee = { 3d 81 [2] 19 8f [2] 32 a3 [2] 1c 81 [2] 08 9a [2] 07 80 [2] 19 9d [2] 1b 9c [2] 00 9a [2] 1c 9d [2] 00 b2 }

  condition:
    any of them
}