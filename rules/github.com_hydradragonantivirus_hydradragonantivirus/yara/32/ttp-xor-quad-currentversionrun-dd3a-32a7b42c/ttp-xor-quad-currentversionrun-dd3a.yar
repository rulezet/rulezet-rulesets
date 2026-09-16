rule TTP_XOR_QUAD_CurrentVersionRun_dd3a {
  strings:
    $key_dd3a = { 8e 55 [2] aa 5b [2] 81 77 [2] af 55 [2] bb 4e [2] b4 54 [2] aa 49 [2] a8 48 [2] b3 4e [2] af 49 [2] b3 66 }

  condition:
    any of them
}