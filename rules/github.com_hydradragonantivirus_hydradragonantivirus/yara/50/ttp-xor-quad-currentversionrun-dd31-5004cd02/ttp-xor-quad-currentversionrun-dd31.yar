rule TTP_XOR_QUAD_CurrentVersionRun_dd31 {
  strings:
    $key_dd31 = { 8e 5e [2] aa 50 [2] 81 7c [2] af 5e [2] bb 45 [2] b4 5f [2] aa 42 [2] a8 43 [2] b3 45 [2] af 42 [2] b3 6d }

  condition:
    any of them
}