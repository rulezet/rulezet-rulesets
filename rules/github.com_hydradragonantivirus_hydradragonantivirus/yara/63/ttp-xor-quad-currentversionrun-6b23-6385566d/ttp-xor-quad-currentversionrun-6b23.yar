rule TTP_XOR_QUAD_CurrentVersionRun_6b23 {
  strings:
    $key_6b23 = { 38 4c [2] 1c 42 [2] 37 6e [2] 19 4c [2] 0d 57 [2] 02 4d [2] 1c 50 [2] 1e 51 [2] 05 57 [2] 19 50 [2] 05 7f }

  condition:
    any of them
}