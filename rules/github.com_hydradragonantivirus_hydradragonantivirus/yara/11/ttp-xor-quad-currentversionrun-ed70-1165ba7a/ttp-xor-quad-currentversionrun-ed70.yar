rule TTP_XOR_QUAD_CurrentVersionRun_ed70 {
  strings:
    $key_ed70 = { be 1f [2] 9a 11 [2] b1 3d [2] 9f 1f [2] 8b 04 [2] 84 1e [2] 9a 03 [2] 98 02 [2] 83 04 [2] 9f 03 [2] 83 2c }

  condition:
    any of them
}