rule TTP_XOR_QUAD_CurrentVersionRun_f8ef {
  strings:
    $key_f8ef = { ab 80 [2] 8f 8e [2] a4 a2 [2] 8a 80 [2] 9e 9b [2] 91 81 [2] 8f 9c [2] 8d 9d [2] 96 9b [2] 8a 9c [2] 96 b3 }

  condition:
    any of them
}