rule TTP_XOR_QUAD_CurrentVersionRun_f149 {
  strings:
    $key_f149 = { a2 26 [2] 86 28 [2] ad 04 [2] 83 26 [2] 97 3d [2] 98 27 [2] 86 3a [2] 84 3b [2] 9f 3d [2] 83 3a [2] 9f 15 }

  condition:
    any of them
}