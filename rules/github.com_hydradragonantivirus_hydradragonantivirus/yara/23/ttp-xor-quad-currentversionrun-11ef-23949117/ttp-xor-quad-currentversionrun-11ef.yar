rule TTP_XOR_QUAD_CurrentVersionRun_11ef {
  strings:
    $key_11ef = { 42 80 [2] 66 8e [2] 4d a2 [2] 63 80 [2] 77 9b [2] 78 81 [2] 66 9c [2] 64 9d [2] 7f 9b [2] 63 9c [2] 7f b3 }

  condition:
    any of them
}