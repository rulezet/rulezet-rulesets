rule TTP_XOR_QUAD_CurrentVersionRun_3da6 {
  strings:
    $key_3da6 = { 6e c9 [2] 4a c7 [2] 61 eb [2] 4f c9 [2] 5b d2 [2] 54 c8 [2] 4a d5 [2] 48 d4 [2] 53 d2 [2] 4f d5 [2] 53 fa }

  condition:
    any of them
}