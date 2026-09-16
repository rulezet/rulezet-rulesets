rule TTP_XOR_QUAD_CurrentVersionRun_fc2d {
  strings:
    $key_fc2d = { af 42 [2] 8b 4c [2] a0 60 [2] 8e 42 [2] 9a 59 [2] 95 43 [2] 8b 5e [2] 89 5f [2] 92 59 [2] 8e 5e [2] 92 71 }

  condition:
    any of them
}