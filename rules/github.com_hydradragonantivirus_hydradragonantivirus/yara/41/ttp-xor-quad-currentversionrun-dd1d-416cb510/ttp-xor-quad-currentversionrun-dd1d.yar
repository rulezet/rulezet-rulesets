rule TTP_XOR_QUAD_CurrentVersionRun_dd1d {
  strings:
    $key_dd1d = { 8e 72 [2] aa 7c [2] 81 50 [2] af 72 [2] bb 69 [2] b4 73 [2] aa 6e [2] a8 6f [2] b3 69 [2] af 6e [2] b3 41 }

  condition:
    any of them
}