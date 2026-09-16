rule TTP_XOR_QUAD_CurrentVersionRun_ddad {
  strings:
    $key_ddad = { 8e c2 [2] aa cc [2] 81 e0 [2] af c2 [2] bb d9 [2] b4 c3 [2] aa de [2] a8 df [2] b3 d9 [2] af de [2] b3 f1 }

  condition:
    any of them
}