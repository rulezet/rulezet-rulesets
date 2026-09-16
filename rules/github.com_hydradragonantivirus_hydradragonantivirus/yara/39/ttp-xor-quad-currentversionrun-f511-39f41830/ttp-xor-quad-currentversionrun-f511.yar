rule TTP_XOR_QUAD_CurrentVersionRun_f511 {
  strings:
    $key_f511 = { a6 7e [2] 82 70 [2] a9 5c [2] 87 7e [2] 93 65 [2] 9c 7f [2] 82 62 [2] 80 63 [2] 9b 65 [2] 87 62 [2] 9b 4d }

  condition:
    any of them
}