rule TTP_XOR_QUAD_CurrentVersionRun_f002 {
  strings:
    $key_f002 = { a3 6d [2] 87 63 [2] ac 4f [2] 82 6d [2] 96 76 [2] 99 6c [2] 87 71 [2] 85 70 [2] 9e 76 [2] 82 71 [2] 9e 5e }

  condition:
    any of them
}