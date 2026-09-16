rule TTP_XOR_QUAD_CurrentVersionRun_dd71 {
  strings:
    $key_dd71 = { 8e 1e [2] aa 10 [2] 81 3c [2] af 1e [2] bb 05 [2] b4 1f [2] aa 02 [2] a8 03 [2] b3 05 [2] af 02 [2] b3 2d }

  condition:
    any of them
}