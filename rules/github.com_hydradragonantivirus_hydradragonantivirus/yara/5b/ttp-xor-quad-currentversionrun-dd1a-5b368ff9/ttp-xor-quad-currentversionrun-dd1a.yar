rule TTP_XOR_QUAD_CurrentVersionRun_dd1a {
  strings:
    $key_dd1a = { 8e 75 [2] aa 7b [2] 81 57 [2] af 75 [2] bb 6e [2] b4 74 [2] aa 69 [2] a8 68 [2] b3 6e [2] af 69 [2] b3 46 }

  condition:
    any of them
}