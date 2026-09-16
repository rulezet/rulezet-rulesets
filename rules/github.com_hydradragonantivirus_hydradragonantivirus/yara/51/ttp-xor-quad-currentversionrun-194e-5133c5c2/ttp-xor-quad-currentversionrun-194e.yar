rule TTP_XOR_QUAD_CurrentVersionRun_194e {
  strings:
    $key_194e = { 4a 21 [2] 6e 2f [2] 45 03 [2] 6b 21 [2] 7f 3a [2] 70 20 [2] 6e 3d [2] 6c 3c [2] 77 3a [2] 6b 3d [2] 77 12 }

  condition:
    any of them
}