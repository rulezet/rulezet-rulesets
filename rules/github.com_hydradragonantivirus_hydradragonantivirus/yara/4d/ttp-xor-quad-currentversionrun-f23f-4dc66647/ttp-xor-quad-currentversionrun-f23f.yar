rule TTP_XOR_QUAD_CurrentVersionRun_f23f {
  strings:
    $key_f23f = { a1 50 [2] 85 5e [2] ae 72 [2] 80 50 [2] 94 4b [2] 9b 51 [2] 85 4c [2] 87 4d [2] 9c 4b [2] 80 4c [2] 9c 63 }

  condition:
    any of them
}