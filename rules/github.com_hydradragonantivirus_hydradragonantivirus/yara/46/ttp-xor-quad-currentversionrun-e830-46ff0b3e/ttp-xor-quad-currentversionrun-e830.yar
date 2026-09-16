rule TTP_XOR_QUAD_CurrentVersionRun_e830 {
  strings:
    $key_e830 = { bb 5f [2] 9f 51 [2] b4 7d [2] 9a 5f [2] 8e 44 [2] 81 5e [2] 9f 43 [2] 9d 42 [2] 86 44 [2] 9a 43 [2] 86 6c }

  condition:
    any of them
}