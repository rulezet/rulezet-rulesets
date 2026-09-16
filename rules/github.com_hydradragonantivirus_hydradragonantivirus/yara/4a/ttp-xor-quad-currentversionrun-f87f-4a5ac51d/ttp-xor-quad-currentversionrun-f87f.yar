rule TTP_XOR_QUAD_CurrentVersionRun_f87f {
  strings:
    $key_f87f = { ab 10 [2] 8f 1e [2] a4 32 [2] 8a 10 [2] 9e 0b [2] 91 11 [2] 8f 0c [2] 8d 0d [2] 96 0b [2] 8a 0c [2] 96 23 }

  condition:
    any of them
}