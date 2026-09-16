rule TTP_XOR_QUAD_CurrentVersionRun_6bef {
  strings:
    $key_6bef = { 38 80 [2] 1c 8e [2] 37 a2 [2] 19 80 [2] 0d 9b [2] 02 81 [2] 1c 9c [2] 1e 9d [2] 05 9b [2] 19 9c [2] 05 b3 }

  condition:
    any of them
}