rule TTP_XOR_QUAD_CurrentVersionRun_deff {
  strings:
    $key_deff = { 8d 90 [2] a9 9e [2] 82 b2 [2] ac 90 [2] b8 8b [2] b7 91 [2] a9 8c [2] ab 8d [2] b0 8b [2] ac 8c [2] b0 a3 }

  condition:
    any of them
}