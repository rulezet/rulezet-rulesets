rule TTP_XOR_QUAD_CurrentVersionRun_8f8a {
  strings:
    $key_8f8a = { dc e5 [2] f8 eb [2] d3 c7 [2] fd e5 [2] e9 fe [2] e6 e4 [2] f8 f9 [2] fa f8 [2] e1 fe [2] fd f9 [2] e1 d6 }

  condition:
    any of them
}