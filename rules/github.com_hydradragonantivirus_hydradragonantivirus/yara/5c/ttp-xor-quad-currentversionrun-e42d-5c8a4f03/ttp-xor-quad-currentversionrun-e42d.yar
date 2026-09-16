rule TTP_XOR_QUAD_CurrentVersionRun_e42d {
  strings:
    $key_e42d = { b7 42 [2] 93 4c [2] b8 60 [2] 96 42 [2] 82 59 [2] 8d 43 [2] 93 5e [2] 91 5f [2] 8a 59 [2] 96 5e [2] 8a 71 }

  condition:
    any of them
}