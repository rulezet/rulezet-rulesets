rule TTP_XOR_QUAD_CurrentVersionRun_ed71 {
  strings:
    $key_ed71 = { be 1e [2] 9a 10 [2] b1 3c [2] 9f 1e [2] 8b 05 [2] 84 1f [2] 9a 02 [2] 98 03 [2] 83 05 [2] 9f 02 [2] 83 2d }

  condition:
    any of them
}