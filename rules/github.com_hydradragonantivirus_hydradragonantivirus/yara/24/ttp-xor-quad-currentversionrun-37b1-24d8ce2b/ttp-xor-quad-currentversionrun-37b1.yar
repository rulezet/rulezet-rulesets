rule TTP_XOR_QUAD_CurrentVersionRun_37b1 {
  strings:
    $key_37b1 = { 64 de [2] 40 d0 [2] 6b fc [2] 45 de [2] 51 c5 [2] 5e df [2] 40 c2 [2] 42 c3 [2] 59 c5 [2] 45 c2 [2] 59 ed }

  condition:
    any of them
}