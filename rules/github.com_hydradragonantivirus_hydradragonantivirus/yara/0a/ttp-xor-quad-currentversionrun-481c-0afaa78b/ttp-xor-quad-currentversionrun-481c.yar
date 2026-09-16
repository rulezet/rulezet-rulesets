rule TTP_XOR_QUAD_CurrentVersionRun_481c {
  strings:
    $key_481c = { 1b 73 [2] 3f 7d [2] 14 51 [2] 3a 73 [2] 2e 68 [2] 21 72 [2] 3f 6f [2] 3d 6e [2] 26 68 [2] 3a 6f [2] 26 40 }

  condition:
    any of them
}