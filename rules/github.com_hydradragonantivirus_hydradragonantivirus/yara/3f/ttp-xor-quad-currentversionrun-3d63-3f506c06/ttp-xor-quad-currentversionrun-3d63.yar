rule TTP_XOR_QUAD_CurrentVersionRun_3d63 {
  strings:
    $key_3d63 = { 6e 0c [2] 4a 02 [2] 61 2e [2] 4f 0c [2] 5b 17 [2] 54 0d [2] 4a 10 [2] 48 11 [2] 53 17 [2] 4f 10 [2] 53 3f }

  condition:
    any of them
}