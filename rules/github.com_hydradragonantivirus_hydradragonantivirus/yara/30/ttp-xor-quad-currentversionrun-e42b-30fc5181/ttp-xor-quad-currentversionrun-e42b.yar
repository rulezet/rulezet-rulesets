rule TTP_XOR_QUAD_CurrentVersionRun_e42b {
  strings:
    $key_e42b = { b7 44 [2] 93 4a [2] b8 66 [2] 96 44 [2] 82 5f [2] 8d 45 [2] 93 58 [2] 91 59 [2] 8a 5f [2] 96 58 [2] 8a 77 }

  condition:
    any of them
}