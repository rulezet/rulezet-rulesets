rule TTP_XOR_QUAD_CurrentVersionRun_e456 {
  strings:
    $key_e456 = { b7 39 [2] 93 37 [2] b8 1b [2] 96 39 [2] 82 22 [2] 8d 38 [2] 93 25 [2] 91 24 [2] 8a 22 [2] 96 25 [2] 8a 0a }

  condition:
    any of them
}