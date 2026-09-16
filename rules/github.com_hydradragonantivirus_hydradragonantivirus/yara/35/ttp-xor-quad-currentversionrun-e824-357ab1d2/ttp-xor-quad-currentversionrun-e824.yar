rule TTP_XOR_QUAD_CurrentVersionRun_e824 {
  strings:
    $key_e824 = { bb 4b [2] 9f 45 [2] b4 69 [2] 9a 4b [2] 8e 50 [2] 81 4a [2] 9f 57 [2] 9d 56 [2] 86 50 [2] 9a 57 [2] 86 78 }

  condition:
    any of them
}