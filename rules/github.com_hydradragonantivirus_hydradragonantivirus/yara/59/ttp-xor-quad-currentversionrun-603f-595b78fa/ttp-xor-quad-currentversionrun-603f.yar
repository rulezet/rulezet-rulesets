rule TTP_XOR_QUAD_CurrentVersionRun_603f {
  strings:
    $key_603f = { 33 50 [2] 17 5e [2] 3c 72 [2] 12 50 [2] 06 4b [2] 09 51 [2] 17 4c [2] 15 4d [2] 0e 4b [2] 12 4c [2] 0e 63 }

  condition:
    any of them
}