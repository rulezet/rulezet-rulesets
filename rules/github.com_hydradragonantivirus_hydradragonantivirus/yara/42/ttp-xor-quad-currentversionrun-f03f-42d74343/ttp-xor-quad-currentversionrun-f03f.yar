rule TTP_XOR_QUAD_CurrentVersionRun_f03f {
  strings:
    $key_f03f = { a3 50 [2] 87 5e [2] ac 72 [2] 82 50 [2] 96 4b [2] 99 51 [2] 87 4c [2] 85 4d [2] 9e 4b [2] 82 4c [2] 9e 63 }

  condition:
    any of them
}