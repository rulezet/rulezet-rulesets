rule TTP_XOR_QUAD_CurrentVersionRun_f249 {
  strings:
    $key_f249 = { a1 26 [2] 85 28 [2] ae 04 [2] 80 26 [2] 94 3d [2] 9b 27 [2] 85 3a [2] 87 3b [2] 9c 3d [2] 80 3a [2] 9c 15 }

  condition:
    any of them
}