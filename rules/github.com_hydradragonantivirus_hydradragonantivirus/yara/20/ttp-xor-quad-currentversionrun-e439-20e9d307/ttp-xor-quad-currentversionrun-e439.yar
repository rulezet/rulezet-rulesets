rule TTP_XOR_QUAD_CurrentVersionRun_e439 {
  strings:
    $key_e439 = { b7 56 [2] 93 58 [2] b8 74 [2] 96 56 [2] 82 4d [2] 8d 57 [2] 93 4a [2] 91 4b [2] 8a 4d [2] 96 4a [2] 8a 65 }

  condition:
    any of them
}