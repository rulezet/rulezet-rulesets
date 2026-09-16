rule TTP_XOR_QUAD_CurrentVersionRun_f81a {
  strings:
    $key_f81a = { ab 75 [2] 8f 7b [2] a4 57 [2] 8a 75 [2] 9e 6e [2] 91 74 [2] 8f 69 [2] 8d 68 [2] 96 6e [2] 8a 69 [2] 96 46 }

  condition:
    any of them
}