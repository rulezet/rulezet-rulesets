rule TTP_XOR_QUAD_CurrentVersionRun_110c {
  strings:
    $key_110c = { 42 63 [2] 66 6d [2] 4d 41 [2] 63 63 [2] 77 78 [2] 78 62 [2] 66 7f [2] 64 7e [2] 7f 78 [2] 63 7f [2] 7f 50 }

  condition:
    any of them
}