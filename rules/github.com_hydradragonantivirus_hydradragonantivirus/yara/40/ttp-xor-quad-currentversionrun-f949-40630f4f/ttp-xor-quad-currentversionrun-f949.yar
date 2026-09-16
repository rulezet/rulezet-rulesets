rule TTP_XOR_QUAD_CurrentVersionRun_f949 {
  strings:
    $key_f949 = { aa 26 [2] 8e 28 [2] a5 04 [2] 8b 26 [2] 9f 3d [2] 90 27 [2] 8e 3a [2] 8c 3b [2] 97 3d [2] 8b 3a [2] 97 15 }

  condition:
    any of them
}