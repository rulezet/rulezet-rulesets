rule TTP_XOR_QUAD_CurrentVersionRun_f812 {
  strings:
    $key_f812 = { ab 7d [2] 8f 73 [2] a4 5f [2] 8a 7d [2] 9e 66 [2] 91 7c [2] 8f 61 [2] 8d 60 [2] 96 66 [2] 8a 61 [2] 96 4e }

  condition:
    any of them
}