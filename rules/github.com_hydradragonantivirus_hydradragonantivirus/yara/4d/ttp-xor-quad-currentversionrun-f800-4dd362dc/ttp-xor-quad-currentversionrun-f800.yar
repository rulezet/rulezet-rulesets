rule TTP_XOR_QUAD_CurrentVersionRun_f800 {
  strings:
    $key_f800 = { ab 6f [2] 8f 61 [2] a4 4d [2] 8a 6f [2] 9e 74 [2] 91 6e [2] 8f 73 [2] 8d 72 [2] 96 74 [2] 8a 73 [2] 96 5c }

  condition:
    any of them
}