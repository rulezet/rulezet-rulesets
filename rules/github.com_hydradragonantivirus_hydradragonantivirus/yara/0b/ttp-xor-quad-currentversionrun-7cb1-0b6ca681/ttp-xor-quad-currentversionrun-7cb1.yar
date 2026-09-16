rule TTP_XOR_QUAD_CurrentVersionRun_7cb1 {
  strings:
    $key_7cb1 = { 2f de [2] 0b d0 [2] 20 fc [2] 0e de [2] 1a c5 [2] 15 df [2] 0b c2 [2] 09 c3 [2] 12 c5 [2] 0e c2 [2] 12 ed }

  condition:
    any of them
}