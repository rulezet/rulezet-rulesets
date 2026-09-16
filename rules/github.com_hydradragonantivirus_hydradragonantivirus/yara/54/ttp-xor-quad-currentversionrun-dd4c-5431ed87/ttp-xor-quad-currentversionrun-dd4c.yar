rule TTP_XOR_QUAD_CurrentVersionRun_dd4c {
  strings:
    $key_dd4c = { 8e 23 [2] aa 2d [2] 81 01 [2] af 23 [2] bb 38 [2] b4 22 [2] aa 3f [2] a8 3e [2] b3 38 [2] af 3f [2] b3 10 }

  condition:
    any of them
}