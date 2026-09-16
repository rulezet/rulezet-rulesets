rule TTP_XOR_QUAD_CurrentVersionRun_e76a {
  strings:
    $key_e76a = { b4 05 [2] 90 0b [2] bb 27 [2] 95 05 [2] 81 1e [2] 8e 04 [2] 90 19 [2] 92 18 [2] 89 1e [2] 95 19 [2] 89 36 }

  condition:
    any of them
}