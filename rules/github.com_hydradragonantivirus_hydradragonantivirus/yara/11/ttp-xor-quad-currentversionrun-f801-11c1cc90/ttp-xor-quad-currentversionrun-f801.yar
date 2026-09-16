rule TTP_XOR_QUAD_CurrentVersionRun_f801 {
  strings:
    $key_f801 = { ab 6e [2] 8f 60 [2] a4 4c [2] 8a 6e [2] 9e 75 [2] 91 6f [2] 8f 72 [2] 8d 73 [2] 96 75 [2] 8a 72 [2] 96 5d }

  condition:
    any of them
}