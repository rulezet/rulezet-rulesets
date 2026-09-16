rule TTP_XOR_QUAD_CurrentVersionRun_3aac {
  strings:
    $key_3aac = { 69 c3 [2] 4d cd [2] 66 e1 [2] 48 c3 [2] 5c d8 [2] 53 c2 [2] 4d df [2] 4f de [2] 54 d8 [2] 48 df [2] 54 f0 }

  condition:
    any of them
}