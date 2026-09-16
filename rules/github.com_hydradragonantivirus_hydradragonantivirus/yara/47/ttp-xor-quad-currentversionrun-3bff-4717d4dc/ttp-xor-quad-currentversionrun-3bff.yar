rule TTP_XOR_QUAD_CurrentVersionRun_3bff {
  strings:
    $key_3bff = { 68 90 [2] 4c 9e [2] 67 b2 [2] 49 90 [2] 5d 8b [2] 52 91 [2] 4c 8c [2] 4e 8d [2] 55 8b [2] 49 8c [2] 55 a3 }

  condition:
    any of them
}