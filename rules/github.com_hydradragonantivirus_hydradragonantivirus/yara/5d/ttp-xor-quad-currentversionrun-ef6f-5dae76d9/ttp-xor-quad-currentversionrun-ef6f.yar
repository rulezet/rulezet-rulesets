rule TTP_XOR_QUAD_CurrentVersionRun_ef6f {
  strings:
    $key_ef6f = { bc 00 [2] 98 0e [2] b3 22 [2] 9d 00 [2] 89 1b [2] 86 01 [2] 98 1c [2] 9a 1d [2] 81 1b [2] 9d 1c [2] 81 33 }

  condition:
    any of them
}