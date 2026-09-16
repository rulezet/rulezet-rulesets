rule TTP_XOR_QUAD_CurrentVersionRun_feb6 {
  strings:
    $key_feb6 = { ad d9 [2] 89 d7 [2] a2 fb [2] 8c d9 [2] 98 c2 [2] 97 d8 [2] 89 c5 [2] 8b c4 [2] 90 c2 [2] 8c c5 [2] 90 ea }

  condition:
    any of them
}