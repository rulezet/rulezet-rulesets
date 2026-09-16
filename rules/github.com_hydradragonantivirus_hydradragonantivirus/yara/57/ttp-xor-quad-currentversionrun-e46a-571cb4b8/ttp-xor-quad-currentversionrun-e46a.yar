rule TTP_XOR_QUAD_CurrentVersionRun_e46a {
  strings:
    $key_e46a = { b7 05 [2] 93 0b [2] b8 27 [2] 96 05 [2] 82 1e [2] 8d 04 [2] 93 19 [2] 91 18 [2] 8a 1e [2] 96 19 [2] 8a 36 }

  condition:
    any of them
}