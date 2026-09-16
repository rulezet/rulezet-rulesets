rule TTP_XOR_QUAD_CurrentVersionRun_e40a {
  strings:
    $key_e40a = { b7 65 [2] 93 6b [2] b8 47 [2] 96 65 [2] 82 7e [2] 8d 64 [2] 93 79 [2] 91 78 [2] 8a 7e [2] 96 79 [2] 8a 56 }

  condition:
    any of them
}