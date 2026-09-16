rule TTP_XOR_QUAD_CurrentVersionRun_e406 {
  strings:
    $key_e406 = { b7 69 [2] 93 67 [2] b8 4b [2] 96 69 [2] 82 72 [2] 8d 68 [2] 93 75 [2] 91 74 [2] 8a 72 [2] 96 75 [2] 8a 5a }

  condition:
    any of them
}