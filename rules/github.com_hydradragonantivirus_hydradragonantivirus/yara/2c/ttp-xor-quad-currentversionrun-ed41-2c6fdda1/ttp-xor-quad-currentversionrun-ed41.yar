rule TTP_XOR_QUAD_CurrentVersionRun_ed41 {
  strings:
    $key_ed41 = { be 2e [2] 9a 20 [2] b1 0c [2] 9f 2e [2] 8b 35 [2] 84 2f [2] 9a 32 [2] 98 33 [2] 83 35 [2] 9f 32 [2] 83 1d }

  condition:
    any of them
}