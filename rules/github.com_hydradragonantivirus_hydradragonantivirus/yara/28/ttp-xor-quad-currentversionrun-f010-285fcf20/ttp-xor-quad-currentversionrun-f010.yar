rule TTP_XOR_QUAD_CurrentVersionRun_f010 {
  strings:
    $key_f010 = { a3 7f [2] 87 71 [2] ac 5d [2] 82 7f [2] 96 64 [2] 99 7e [2] 87 63 [2] 85 62 [2] 9e 64 [2] 82 63 [2] 9e 4c }

  condition:
    any of them
}