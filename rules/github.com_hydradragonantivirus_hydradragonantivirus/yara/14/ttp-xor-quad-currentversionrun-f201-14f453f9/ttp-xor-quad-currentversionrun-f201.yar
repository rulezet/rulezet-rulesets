rule TTP_XOR_QUAD_CurrentVersionRun_f201 {
  strings:
    $key_f201 = { a1 6e [2] 85 60 [2] ae 4c [2] 80 6e [2] 94 75 [2] 9b 6f [2] 85 72 [2] 87 73 [2] 9c 75 [2] 80 72 [2] 9c 5d }

  condition:
    any of them
}