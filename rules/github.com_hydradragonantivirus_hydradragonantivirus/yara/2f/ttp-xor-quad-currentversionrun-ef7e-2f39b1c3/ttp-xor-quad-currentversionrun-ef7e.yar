rule TTP_XOR_QUAD_CurrentVersionRun_ef7e {
  strings:
    $key_ef7e = { bc 11 [2] 98 1f [2] b3 33 [2] 9d 11 [2] 89 0a [2] 86 10 [2] 98 0d [2] 9a 0c [2] 81 0a [2] 9d 0d [2] 81 22 }

  condition:
    any of them
}