rule TTP_XOR_QUAD_CurrentVersionRun_f00d {
  strings:
    $key_f00d = { a3 62 [2] 87 6c [2] ac 40 [2] 82 62 [2] 96 79 [2] 99 63 [2] 87 7e [2] 85 7f [2] 9e 79 [2] 82 7e [2] 9e 51 }

  condition:
    any of them
}