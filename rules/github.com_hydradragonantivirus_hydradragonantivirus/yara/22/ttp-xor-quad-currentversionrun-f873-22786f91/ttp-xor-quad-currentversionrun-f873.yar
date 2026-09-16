rule TTP_XOR_QUAD_CurrentVersionRun_f873 {
  strings:
    $key_f873 = { ab 1c [2] 8f 12 [2] a4 3e [2] 8a 1c [2] 9e 07 [2] 91 1d [2] 8f 00 [2] 8d 01 [2] 96 07 [2] 8a 00 [2] 96 2f }

  condition:
    any of them
}