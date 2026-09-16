rule TTP_XOR_QUAD_CurrentVersionRun_f2ee {
  strings:
    $key_f2ee = { a1 81 [2] 85 8f [2] ae a3 [2] 80 81 [2] 94 9a [2] 9b 80 [2] 85 9d [2] 87 9c [2] 9c 9a [2] 80 9d [2] 9c b2 }

  condition:
    any of them
}