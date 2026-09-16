rule TTP_XOR_QUAD_CurrentVersionRun_e40f {
  strings:
    $key_e40f = { b7 60 [2] 93 6e [2] b8 42 [2] 96 60 [2] 82 7b [2] 8d 61 [2] 93 7c [2] 91 7d [2] 8a 7b [2] 96 7c [2] 8a 53 }

  condition:
    any of them
}