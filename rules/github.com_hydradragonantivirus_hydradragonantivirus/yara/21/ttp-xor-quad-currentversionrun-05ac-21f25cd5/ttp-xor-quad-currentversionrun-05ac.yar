rule TTP_XOR_QUAD_CurrentVersionRun_05ac {
  strings:
    $key_05ac = { 56 c3 [2] 72 cd [2] 59 e1 [2] 77 c3 [2] 63 d8 [2] 6c c2 [2] 72 df [2] 70 de [2] 6b d8 [2] 77 df [2] 6b f0 }

  condition:
    any of them
}