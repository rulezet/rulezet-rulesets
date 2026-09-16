rule TTP_XOR_QUAD_CurrentVersionRun_11ec {
  strings:
    $key_11ec = { 42 83 [2] 66 8d [2] 4d a1 [2] 63 83 [2] 77 98 [2] 78 82 [2] 66 9f [2] 64 9e [2] 7f 98 [2] 63 9f [2] 7f b0 }

  condition:
    any of them
}