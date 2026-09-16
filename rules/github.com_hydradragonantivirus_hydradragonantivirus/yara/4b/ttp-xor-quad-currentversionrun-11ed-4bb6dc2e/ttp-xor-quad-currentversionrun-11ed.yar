rule TTP_XOR_QUAD_CurrentVersionRun_11ed {
  strings:
    $key_11ed = { 42 82 [2] 66 8c [2] 4d a0 [2] 63 82 [2] 77 99 [2] 78 83 [2] 66 9e [2] 64 9f [2] 7f 99 [2] 63 9e [2] 7f b1 }

  condition:
    any of them
}