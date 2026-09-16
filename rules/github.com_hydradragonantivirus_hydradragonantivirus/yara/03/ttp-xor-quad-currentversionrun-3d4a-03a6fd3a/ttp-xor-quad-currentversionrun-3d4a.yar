rule TTP_XOR_QUAD_CurrentVersionRun_3d4a {
  strings:
    $key_3d4a = { 6e 25 [2] 4a 2b [2] 61 07 [2] 4f 25 [2] 5b 3e [2] 54 24 [2] 4a 39 [2] 48 38 [2] 53 3e [2] 4f 39 [2] 53 16 }

  condition:
    any of them
}