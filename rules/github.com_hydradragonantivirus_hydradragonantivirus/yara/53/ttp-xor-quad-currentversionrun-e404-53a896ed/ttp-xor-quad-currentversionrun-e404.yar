rule TTP_XOR_QUAD_CurrentVersionRun_e404 {
  strings:
    $key_e404 = { b7 6b [2] 93 65 [2] b8 49 [2] 96 6b [2] 82 70 [2] 8d 6a [2] 93 77 [2] 91 76 [2] 8a 70 [2] 96 77 [2] 8a 58 }

  condition:
    any of them
}