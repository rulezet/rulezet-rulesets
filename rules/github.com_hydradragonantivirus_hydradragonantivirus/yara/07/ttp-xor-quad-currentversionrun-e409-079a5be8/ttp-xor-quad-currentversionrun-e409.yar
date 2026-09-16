rule TTP_XOR_QUAD_CurrentVersionRun_e409 {
  strings:
    $key_e409 = { b7 66 [2] 93 68 [2] b8 44 [2] 96 66 [2] 82 7d [2] 8d 67 [2] 93 7a [2] 91 7b [2] 8a 7d [2] 96 7a [2] 8a 55 }

  condition:
    any of them
}