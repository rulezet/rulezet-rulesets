rule TTP_XOR_QUAD_CurrentVersionRun_3d6d {
  strings:
    $key_3d6d = { 6e 02 [2] 4a 0c [2] 61 20 [2] 4f 02 [2] 5b 19 [2] 54 03 [2] 4a 1e [2] 48 1f [2] 53 19 [2] 4f 1e [2] 53 31 }

  condition:
    any of them
}