rule TTP_XOR_QUAD_CurrentVersionRun_e42a {
  strings:
    $key_e42a = { b7 45 [2] 93 4b [2] b8 67 [2] 96 45 [2] 82 5e [2] 8d 44 [2] 93 59 [2] 91 58 [2] 8a 5e [2] 96 59 [2] 8a 76 }

  condition:
    any of them
}