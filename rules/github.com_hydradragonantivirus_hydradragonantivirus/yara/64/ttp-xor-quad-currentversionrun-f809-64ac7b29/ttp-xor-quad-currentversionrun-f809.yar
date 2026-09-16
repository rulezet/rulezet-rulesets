rule TTP_XOR_QUAD_CurrentVersionRun_f809 {
  strings:
    $key_f809 = { ab 66 [2] 8f 68 [2] a4 44 [2] 8a 66 [2] 9e 7d [2] 91 67 [2] 8f 7a [2] 8d 7b [2] 96 7d [2] 8a 7a [2] 96 55 }

  condition:
    any of them
}