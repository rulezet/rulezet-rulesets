rule TTP_XOR_QUAD_CurrentVersionRun_f8ff {
  strings:
    $key_f8ff = { ab 90 [2] 8f 9e [2] a4 b2 [2] 8a 90 [2] 9e 8b [2] 91 91 [2] 8f 8c [2] 8d 8d [2] 96 8b [2] 8a 8c [2] 96 a3 }

  condition:
    any of them
}