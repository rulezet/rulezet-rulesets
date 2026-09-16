rule TTP_XOR_QUAD_CurrentVersionRun_f712 {
  strings:
    $key_f712 = { a4 7d [2] 80 73 [2] ab 5f [2] 85 7d [2] 91 66 [2] 9e 7c [2] 80 61 [2] 82 60 [2] 99 66 [2] 85 61 [2] 99 4e }

  condition:
    any of them
}