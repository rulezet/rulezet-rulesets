rule TTP_XOR_QUAD_CurrentVersionRun_3d7a {
  strings:
    $key_3d7a = { 6e 15 [2] 4a 1b [2] 61 37 [2] 4f 15 [2] 5b 0e [2] 54 14 [2] 4a 09 [2] 48 08 [2] 53 0e [2] 4f 09 [2] 53 26 }

  condition:
    any of them
}