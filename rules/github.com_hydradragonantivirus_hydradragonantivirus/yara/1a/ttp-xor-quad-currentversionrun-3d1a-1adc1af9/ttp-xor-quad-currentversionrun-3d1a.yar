rule TTP_XOR_QUAD_CurrentVersionRun_3d1a {
  strings:
    $key_3d1a = { 6e 75 [2] 4a 7b [2] 61 57 [2] 4f 75 [2] 5b 6e [2] 54 74 [2] 4a 69 [2] 48 68 [2] 53 6e [2] 4f 69 [2] 53 46 }

  condition:
    any of them
}