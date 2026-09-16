rule TTP_XOR_QUAD_CurrentVersionRun_f830 {
  strings:
    $key_f830 = { ab 5f [2] 8f 51 [2] a4 7d [2] 8a 5f [2] 9e 44 [2] 91 5e [2] 8f 43 [2] 8d 42 [2] 96 44 [2] 8a 43 [2] 96 6c }

  condition:
    any of them
}