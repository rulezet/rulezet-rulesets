rule TTP_XOR_QUAD_CurrentVersionRun_3d6c {
  strings:
    $key_3d6c = { 6e 03 [2] 4a 0d [2] 61 21 [2] 4f 03 [2] 5b 18 [2] 54 02 [2] 4a 1f [2] 48 1e [2] 53 18 [2] 4f 1f [2] 53 30 }

  condition:
    any of them
}