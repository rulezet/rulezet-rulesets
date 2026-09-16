rule TTP_XOR_QUAD_CurrentVersionRun_dd4e {
  strings:
    $key_dd4e = { 8e 21 [2] aa 2f [2] 81 03 [2] af 21 [2] bb 3a [2] b4 20 [2] aa 3d [2] a8 3c [2] b3 3a [2] af 3d [2] b3 12 }

  condition:
    any of them
}