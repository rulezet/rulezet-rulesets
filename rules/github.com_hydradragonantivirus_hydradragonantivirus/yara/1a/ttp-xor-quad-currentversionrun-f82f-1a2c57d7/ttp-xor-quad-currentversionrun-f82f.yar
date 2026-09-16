rule TTP_XOR_QUAD_CurrentVersionRun_f82f {
  strings:
    $key_f82f = { ab 40 [2] 8f 4e [2] a4 62 [2] 8a 40 [2] 9e 5b [2] 91 41 [2] 8f 5c [2] 8d 5d [2] 96 5b [2] 8a 5c [2] 96 73 }

  condition:
    any of them
}