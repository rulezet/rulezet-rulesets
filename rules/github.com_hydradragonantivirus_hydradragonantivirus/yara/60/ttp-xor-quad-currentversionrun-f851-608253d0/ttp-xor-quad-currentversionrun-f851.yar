rule TTP_XOR_QUAD_CurrentVersionRun_f851 {
  strings:
    $key_f851 = { ab 3e [2] 8f 30 [2] a4 1c [2] 8a 3e [2] 9e 25 [2] 91 3f [2] 8f 22 [2] 8d 23 [2] 96 25 [2] 8a 22 [2] 96 0d }

  condition:
    any of them
}