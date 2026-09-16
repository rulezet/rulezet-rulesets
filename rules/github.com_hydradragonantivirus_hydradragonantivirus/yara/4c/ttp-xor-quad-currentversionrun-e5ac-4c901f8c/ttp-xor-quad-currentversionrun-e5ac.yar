rule TTP_XOR_QUAD_CurrentVersionRun_e5ac {
  strings:
    $key_e5ac = { b6 c3 [2] 92 cd [2] b9 e1 [2] 97 c3 [2] 83 d8 [2] 8c c2 [2] 92 df [2] 90 de [2] 8b d8 [2] 97 df [2] 8b f0 }

  condition:
    any of them
}