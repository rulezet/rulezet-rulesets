rule TTP_XOR_QUAD_CurrentVersionRun_e1ed {
  strings:
    $key_e1ed = { b2 82 [2] 96 8c [2] bd a0 [2] 93 82 [2] 87 99 [2] 88 83 [2] 96 9e [2] 94 9f [2] 8f 99 [2] 93 9e [2] 8f b1 }

  condition:
    any of them
}