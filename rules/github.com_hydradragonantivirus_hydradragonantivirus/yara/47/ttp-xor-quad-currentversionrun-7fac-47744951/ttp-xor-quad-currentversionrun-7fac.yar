rule TTP_XOR_QUAD_CurrentVersionRun_7fac {
  strings:
    $key_7fac = { 2c c3 [2] 08 cd [2] 23 e1 [2] 0d c3 [2] 19 d8 [2] 16 c2 [2] 08 df [2] 0a de [2] 11 d8 [2] 0d df [2] 11 f0 }

  condition:
    any of them
}