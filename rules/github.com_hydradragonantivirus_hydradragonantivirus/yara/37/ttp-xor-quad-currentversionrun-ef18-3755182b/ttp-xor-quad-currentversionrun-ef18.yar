rule TTP_XOR_QUAD_CurrentVersionRun_ef18 {
  strings:
    $key_ef18 = { bc 77 [2] 98 79 [2] b3 55 [2] 9d 77 [2] 89 6c [2] 86 76 [2] 98 6b [2] 9a 6a [2] 81 6c [2] 9d 6b [2] 81 44 }

  condition:
    any of them
}