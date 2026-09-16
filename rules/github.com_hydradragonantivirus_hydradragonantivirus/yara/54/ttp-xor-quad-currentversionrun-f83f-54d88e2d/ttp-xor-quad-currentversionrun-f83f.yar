rule TTP_XOR_QUAD_CurrentVersionRun_f83f {
  strings:
    $key_f83f = { ab 50 [2] 8f 5e [2] a4 72 [2] 8a 50 [2] 9e 4b [2] 91 51 [2] 8f 4c [2] 8d 4d [2] 96 4b [2] 8a 4c [2] 96 63 }

  condition:
    any of them
}