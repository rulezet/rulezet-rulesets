rule TTP_XOR_QUAD_CurrentVersionRun_3d50 {
  strings:
    $key_3d50 = { 6e 3f [2] 4a 31 [2] 61 1d [2] 4f 3f [2] 5b 24 [2] 54 3e [2] 4a 23 [2] 48 22 [2] 53 24 [2] 4f 23 [2] 53 0c }

  condition:
    any of them
}