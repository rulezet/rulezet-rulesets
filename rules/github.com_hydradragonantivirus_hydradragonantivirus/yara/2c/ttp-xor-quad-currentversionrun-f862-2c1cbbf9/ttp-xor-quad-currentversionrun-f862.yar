rule TTP_XOR_QUAD_CurrentVersionRun_f862 {
  strings:
    $key_f862 = { ab 0d [2] 8f 03 [2] a4 2f [2] 8a 0d [2] 9e 16 [2] 91 0c [2] 8f 11 [2] 8d 10 [2] 96 16 [2] 8a 11 [2] 96 3e }

  condition:
    any of them
}