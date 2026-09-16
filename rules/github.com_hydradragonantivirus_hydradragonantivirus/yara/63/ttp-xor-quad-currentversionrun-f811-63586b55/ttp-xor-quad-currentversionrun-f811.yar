rule TTP_XOR_QUAD_CurrentVersionRun_f811 {
  strings:
    $key_f811 = { ab 7e [2] 8f 70 [2] a4 5c [2] 8a 7e [2] 9e 65 [2] 91 7f [2] 8f 62 [2] 8d 63 [2] 96 65 [2] 8a 62 [2] 96 4d }

  condition:
    any of them
}