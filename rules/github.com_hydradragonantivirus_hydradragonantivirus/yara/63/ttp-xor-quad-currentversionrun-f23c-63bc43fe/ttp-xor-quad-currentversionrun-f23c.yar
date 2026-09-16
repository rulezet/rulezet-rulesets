rule TTP_XOR_QUAD_CurrentVersionRun_f23c {
  strings:
    $key_f23c = { a1 53 [2] 85 5d [2] ae 71 [2] 80 53 [2] 94 48 [2] 9b 52 [2] 85 4f [2] 87 4e [2] 9c 48 [2] 80 4f [2] 9c 60 }

  condition:
    any of them
}