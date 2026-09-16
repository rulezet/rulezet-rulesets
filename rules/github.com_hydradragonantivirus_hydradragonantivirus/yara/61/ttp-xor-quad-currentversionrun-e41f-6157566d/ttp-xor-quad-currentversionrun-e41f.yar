rule TTP_XOR_QUAD_CurrentVersionRun_e41f {
  strings:
    $key_e41f = { b7 70 [2] 93 7e [2] b8 52 [2] 96 70 [2] 82 6b [2] 8d 71 [2] 93 6c [2] 91 6d [2] 8a 6b [2] 96 6c [2] 8a 43 }

  condition:
    any of them
}