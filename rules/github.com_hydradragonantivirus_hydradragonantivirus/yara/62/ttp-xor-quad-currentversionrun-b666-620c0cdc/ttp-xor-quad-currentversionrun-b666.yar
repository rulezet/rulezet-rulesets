rule TTP_XOR_QUAD_CurrentVersionRun_b666 {
  strings:
    $key_b666 = { e5 09 [2] c1 07 [2] ea 2b [2] c4 09 [2] d0 12 [2] df 08 [2] c1 15 [2] c3 14 [2] d8 12 [2] c4 15 [2] d8 3a }

  condition:
    any of them
}