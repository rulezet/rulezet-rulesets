rule TTP_XOR_QUAD_CurrentVersionRun_e424 {
  strings:
    $key_e424 = { b7 4b [2] 93 45 [2] b8 69 [2] 96 4b [2] 82 50 [2] 8d 4a [2] 93 57 [2] 91 56 [2] 8a 50 [2] 96 57 [2] 8a 78 }

  condition:
    any of them
}