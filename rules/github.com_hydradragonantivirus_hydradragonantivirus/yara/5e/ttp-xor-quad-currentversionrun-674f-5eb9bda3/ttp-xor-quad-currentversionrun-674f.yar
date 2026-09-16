rule TTP_XOR_QUAD_CurrentVersionRun_674f {
  strings:
    $key_674f = { 34 20 [2] 10 2e [2] 3b 02 [2] 15 20 [2] 01 3b [2] 0e 21 [2] 10 3c [2] 12 3d [2] 09 3b [2] 15 3c [2] 09 13 }

  condition:
    any of them
}