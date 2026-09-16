rule TTP_XOR_QUAD_CurrentVersionRun_116d {
  strings:
    $key_116d = { 42 02 [2] 66 0c [2] 4d 20 [2] 63 02 [2] 77 19 [2] 78 03 [2] 66 1e [2] 64 1f [2] 7f 19 [2] 63 1e [2] 7f 31 }

  condition:
    any of them
}