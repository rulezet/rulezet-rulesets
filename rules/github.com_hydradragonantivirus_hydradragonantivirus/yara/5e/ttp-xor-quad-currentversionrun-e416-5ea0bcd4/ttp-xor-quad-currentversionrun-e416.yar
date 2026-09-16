rule TTP_XOR_QUAD_CurrentVersionRun_e416 {
  strings:
    $key_e416 = { b7 79 [2] 93 77 [2] b8 5b [2] 96 79 [2] 82 62 [2] 8d 78 [2] 93 65 [2] 91 64 [2] 8a 62 [2] 96 65 [2] 8a 4a }

  condition:
    any of them
}