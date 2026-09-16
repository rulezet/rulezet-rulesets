rule TTP_XOR_QUAD_CurrentVersionRun_5fac {
  strings:
    $key_5fac = { 0c c3 [2] 28 cd [2] 03 e1 [2] 2d c3 [2] 39 d8 [2] 36 c2 [2] 28 df [2] 2a de [2] 31 d8 [2] 2d df [2] 31 f0 }

  condition:
    any of them
}