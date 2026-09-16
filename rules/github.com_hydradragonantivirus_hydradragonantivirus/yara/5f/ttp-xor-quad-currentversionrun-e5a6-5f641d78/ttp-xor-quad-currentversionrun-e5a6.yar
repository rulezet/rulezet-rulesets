rule TTP_XOR_QUAD_CurrentVersionRun_e5a6 {
  strings:
    $key_e5a6 = { b6 c9 [2] 92 c7 [2] b9 eb [2] 97 c9 [2] 83 d2 [2] 8c c8 [2] 92 d5 [2] 90 d4 [2] 8b d2 [2] 97 d5 [2] 8b fa }

  condition:
    any of them
}