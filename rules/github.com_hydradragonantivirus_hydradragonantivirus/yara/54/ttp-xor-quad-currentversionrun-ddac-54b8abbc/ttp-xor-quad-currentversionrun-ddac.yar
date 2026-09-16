rule TTP_XOR_QUAD_CurrentVersionRun_ddac {
  strings:
    $key_ddac = { 8e c3 [2] aa cd [2] 81 e1 [2] af c3 [2] bb d8 [2] b4 c2 [2] aa df [2] a8 de [2] b3 d8 [2] af df [2] b3 f0 }

  condition:
    any of them
}