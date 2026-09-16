rule TTP_XOR_QUAD_CurrentVersionRun_ef4c {
  strings:
    $key_ef4c = { bc 23 [2] 98 2d [2] b3 01 [2] 9d 23 [2] 89 38 [2] 86 22 [2] 98 3f [2] 9a 3e [2] 81 38 [2] 9d 3f [2] 81 10 }

  condition:
    any of them
}