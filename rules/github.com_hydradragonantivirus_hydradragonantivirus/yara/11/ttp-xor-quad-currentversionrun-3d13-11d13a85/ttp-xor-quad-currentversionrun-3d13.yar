rule TTP_XOR_QUAD_CurrentVersionRun_3d13 {
  strings:
    $key_3d13 = { 6e 7c [2] 4a 72 [2] 61 5e [2] 4f 7c [2] 5b 67 [2] 54 7d [2] 4a 60 [2] 48 61 [2] 53 67 [2] 4f 60 [2] 53 4f }

  condition:
    any of them
}