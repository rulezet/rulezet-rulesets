rule TTP_XOR_QUAD_CurrentVersionRun_f8ec {
  strings:
    $key_f8ec = { ab 83 [2] 8f 8d [2] a4 a1 [2] 8a 83 [2] 9e 98 [2] 91 82 [2] 8f 9f [2] 8d 9e [2] 96 98 [2] 8a 9f [2] 96 b0 }

  condition:
    any of them
}