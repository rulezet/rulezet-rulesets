rule TTP_XOR_QUAD_CurrentVersionRun_e41c {
  strings:
    $key_e41c = { b7 73 [2] 93 7d [2] b8 51 [2] 96 73 [2] 82 68 [2] 8d 72 [2] 93 6f [2] 91 6e [2] 8a 68 [2] 96 6f [2] 8a 40 }

  condition:
    any of them
}