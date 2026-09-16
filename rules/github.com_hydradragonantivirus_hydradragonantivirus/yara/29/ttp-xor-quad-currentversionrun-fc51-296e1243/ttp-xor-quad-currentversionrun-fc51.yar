rule TTP_XOR_QUAD_CurrentVersionRun_fc51 {
  strings:
    $key_fc51 = { af 3e [2] 8b 30 [2] a0 1c [2] 8e 3e [2] 9a 25 [2] 95 3f [2] 8b 22 [2] 89 23 [2] 92 25 [2] 8e 22 [2] 92 0d }

  condition:
    any of them
}