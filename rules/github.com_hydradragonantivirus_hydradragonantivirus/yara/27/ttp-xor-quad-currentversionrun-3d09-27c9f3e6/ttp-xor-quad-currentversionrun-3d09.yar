rule TTP_XOR_QUAD_CurrentVersionRun_3d09 {
  strings:
    $key_3d09 = { 6e 66 [2] 4a 68 [2] 61 44 [2] 4f 66 [2] 5b 7d [2] 54 67 [2] 4a 7a [2] 48 7b [2] 53 7d [2] 4f 7a [2] 53 55 }

  condition:
    any of them
}