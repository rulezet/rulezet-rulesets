rule TTP_XOR_QUAD_CurrentVersionRun_e48a {
  strings:
    $key_e48a = { b7 e5 [2] 93 eb [2] b8 c7 [2] 96 e5 [2] 82 fe [2] 8d e4 [2] 93 f9 [2] 91 f8 [2] 8a fe [2] 96 f9 [2] 8a d6 }

  condition:
    any of them
}