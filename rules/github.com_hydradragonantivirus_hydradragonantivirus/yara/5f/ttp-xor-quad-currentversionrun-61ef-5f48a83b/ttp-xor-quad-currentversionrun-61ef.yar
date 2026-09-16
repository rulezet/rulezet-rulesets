rule TTP_XOR_QUAD_CurrentVersionRun_61ef {
  strings:
    $key_61ef = { 32 80 [2] 16 8e [2] 3d a2 [2] 13 80 [2] 07 9b [2] 08 81 [2] 16 9c [2] 14 9d [2] 0f 9b [2] 13 9c [2] 0f b3 }

  condition:
    any of them
}