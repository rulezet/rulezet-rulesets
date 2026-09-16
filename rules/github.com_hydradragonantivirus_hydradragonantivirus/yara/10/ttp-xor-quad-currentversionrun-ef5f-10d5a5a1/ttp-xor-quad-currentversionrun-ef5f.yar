rule TTP_XOR_QUAD_CurrentVersionRun_ef5f {
  strings:
    $key_ef5f = { bc 30 [2] 98 3e [2] b3 12 [2] 9d 30 [2] 89 2b [2] 86 31 [2] 98 2c [2] 9a 2d [2] 81 2b [2] 9d 2c [2] 81 03 }

  condition:
    any of them
}