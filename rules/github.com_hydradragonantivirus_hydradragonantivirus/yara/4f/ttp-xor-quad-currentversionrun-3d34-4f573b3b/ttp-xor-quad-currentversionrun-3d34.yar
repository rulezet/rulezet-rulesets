rule TTP_XOR_QUAD_CurrentVersionRun_3d34 {
  strings:
    $key_3d34 = { 6e 5b [2] 4a 55 [2] 61 79 [2] 4f 5b [2] 5b 40 [2] 54 5a [2] 4a 47 [2] 48 46 [2] 53 40 [2] 4f 47 [2] 53 68 }

  condition:
    any of them
}