rule TTP_XOR_QUAD_CurrentVersionRun_3d08 {
  strings:
    $key_3d08 = { 6e 67 [2] 4a 69 [2] 61 45 [2] 4f 67 [2] 5b 7c [2] 54 66 [2] 4a 7b [2] 48 7a [2] 53 7c [2] 4f 7b [2] 53 54 }

  condition:
    any of them
}