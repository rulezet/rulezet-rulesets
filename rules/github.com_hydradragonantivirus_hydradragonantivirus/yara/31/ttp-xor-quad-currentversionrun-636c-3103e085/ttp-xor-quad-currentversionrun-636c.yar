rule TTP_XOR_QUAD_CurrentVersionRun_636c {
  strings:
    $key_636c = { 30 03 [2] 14 0d [2] 3f 21 [2] 11 03 [2] 05 18 [2] 0a 02 [2] 14 1f [2] 16 1e [2] 0d 18 [2] 11 1f [2] 0d 30 }

  condition:
    any of them
}