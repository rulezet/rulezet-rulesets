rule TTP_XOR_QUAD_CurrentVersionRun_f22e {
  strings:
    $key_f22e = { a1 41 [2] 85 4f [2] ae 63 [2] 80 41 [2] 94 5a [2] 9b 40 [2] 85 5d [2] 87 5c [2] 9c 5a [2] 80 5d [2] 9c 72 }

  condition:
    any of them
}