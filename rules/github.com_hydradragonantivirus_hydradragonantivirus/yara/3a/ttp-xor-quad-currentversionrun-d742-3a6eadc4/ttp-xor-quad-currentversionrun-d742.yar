rule TTP_XOR_QUAD_CurrentVersionRun_d742 {
  strings:
    $key_d742 = { 84 2d [2] a0 23 [2] 8b 0f [2] a5 2d [2] b1 36 [2] be 2c [2] a0 31 [2] a2 30 [2] b9 36 [2] a5 31 [2] b9 1e }

  condition:
    any of them
}