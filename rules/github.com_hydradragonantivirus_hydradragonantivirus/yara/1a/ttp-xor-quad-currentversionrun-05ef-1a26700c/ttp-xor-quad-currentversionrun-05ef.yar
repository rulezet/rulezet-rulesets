rule TTP_XOR_QUAD_CurrentVersionRun_05ef {
  strings:
    $key_05ef = { 56 80 [2] 72 8e [2] 59 a2 [2] 77 80 [2] 63 9b [2] 6c 81 [2] 72 9c [2] 70 9d [2] 6b 9b [2] 77 9c [2] 6b b3 }

  condition:
    any of them
}