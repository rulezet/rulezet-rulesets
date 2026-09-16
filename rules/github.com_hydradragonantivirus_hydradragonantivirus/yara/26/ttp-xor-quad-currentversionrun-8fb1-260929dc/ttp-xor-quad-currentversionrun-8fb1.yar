rule TTP_XOR_QUAD_CurrentVersionRun_8fb1 {
  strings:
    $key_8fb1 = { dc de [2] f8 d0 [2] d3 fc [2] fd de [2] e9 c5 [2] e6 df [2] f8 c2 [2] fa c3 [2] e1 c5 [2] fd c2 [2] e1 ed }

  condition:
    any of them
}