rule TTP_XOR_QUAD_CurrentVersionRun_f412 {
  strings:
    $key_f412 = { a7 7d [2] 83 73 [2] a8 5f [2] 86 7d [2] 92 66 [2] 9d 7c [2] 83 61 [2] 81 60 [2] 9a 66 [2] 86 61 [2] 9a 4e }

  condition:
    any of them
}