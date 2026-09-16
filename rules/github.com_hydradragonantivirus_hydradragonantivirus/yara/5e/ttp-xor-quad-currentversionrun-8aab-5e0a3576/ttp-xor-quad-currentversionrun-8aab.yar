rule TTP_XOR_QUAD_CurrentVersionRun_8aab {
  strings:
    $key_8aab = { d9 c4 [2] fd ca [2] d6 e6 [2] f8 c4 [2] ec df [2] e3 c5 [2] fd d8 [2] ff d9 [2] e4 df [2] f8 d8 [2] e4 f7 }

  condition:
    any of them
}