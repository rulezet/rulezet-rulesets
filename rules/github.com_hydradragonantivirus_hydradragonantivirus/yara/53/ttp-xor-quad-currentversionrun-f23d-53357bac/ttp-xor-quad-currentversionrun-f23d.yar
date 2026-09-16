rule TTP_XOR_QUAD_CurrentVersionRun_f23d {
  strings:
    $key_f23d = { a1 52 [2] 85 5c [2] ae 70 [2] 80 52 [2] 94 49 [2] 9b 53 [2] 85 4e [2] 87 4f [2] 9c 49 [2] 80 4e [2] 9c 61 }

  condition:
    any of them
}