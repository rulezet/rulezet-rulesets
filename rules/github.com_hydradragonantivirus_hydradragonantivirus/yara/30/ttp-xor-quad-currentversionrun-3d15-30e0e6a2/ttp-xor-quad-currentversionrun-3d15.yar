rule TTP_XOR_QUAD_CurrentVersionRun_3d15 {
  strings:
    $key_3d15 = { 6e 7a [2] 4a 74 [2] 61 58 [2] 4f 7a [2] 5b 61 [2] 54 7b [2] 4a 66 [2] 48 67 [2] 53 61 [2] 4f 66 [2] 53 49 }

  condition:
    any of them
}