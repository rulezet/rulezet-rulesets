rule TTP_XOR_QUAD_CurrentVersionRun_f87d {
  strings:
    $key_f87d = { ab 12 [2] 8f 1c [2] a4 30 [2] 8a 12 [2] 9e 09 [2] 91 13 [2] 8f 0e [2] 8d 0f [2] 96 09 [2] 8a 0e [2] 96 21 }

  condition:
    any of them
}