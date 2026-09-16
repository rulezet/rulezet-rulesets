rule TTP_XOR_QUAD_CurrentVersionRun_dfac {
  strings:
    $key_dfac = { 8c c3 [2] a8 cd [2] 83 e1 [2] ad c3 [2] b9 d8 [2] b6 c2 [2] a8 df [2] aa de [2] b1 d8 [2] ad df [2] b1 f0 }

  condition:
    any of them
}