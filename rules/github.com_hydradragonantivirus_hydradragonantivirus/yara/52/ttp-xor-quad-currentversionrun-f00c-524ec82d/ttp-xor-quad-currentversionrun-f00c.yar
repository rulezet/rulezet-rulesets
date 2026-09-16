rule TTP_XOR_QUAD_CurrentVersionRun_f00c {
  strings:
    $key_f00c = { a3 63 [2] 87 6d [2] ac 41 [2] 82 63 [2] 96 78 [2] 99 62 [2] 87 7f [2] 85 7e [2] 9e 78 [2] 82 7f [2] 9e 50 }

  condition:
    any of them
}