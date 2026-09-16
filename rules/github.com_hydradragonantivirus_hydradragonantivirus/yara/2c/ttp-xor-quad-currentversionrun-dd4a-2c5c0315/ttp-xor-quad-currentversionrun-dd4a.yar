rule TTP_XOR_QUAD_CurrentVersionRun_dd4a {
  strings:
    $key_dd4a = { 8e 25 [2] aa 2b [2] 81 07 [2] af 25 [2] bb 3e [2] b4 24 [2] aa 39 [2] a8 38 [2] b3 3e [2] af 39 [2] b3 16 }

  condition:
    any of them
}