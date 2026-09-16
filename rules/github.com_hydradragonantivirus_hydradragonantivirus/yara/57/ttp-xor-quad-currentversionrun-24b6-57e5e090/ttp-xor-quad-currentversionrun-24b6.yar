rule TTP_XOR_QUAD_CurrentVersionRun_24b6 {
  strings:
    $key_24b6 = { 77 d9 [2] 53 d7 [2] 78 fb [2] 56 d9 [2] 42 c2 [2] 4d d8 [2] 53 c5 [2] 51 c4 [2] 4a c2 [2] 56 c5 [2] 4a ea }

  condition:
    any of them
}