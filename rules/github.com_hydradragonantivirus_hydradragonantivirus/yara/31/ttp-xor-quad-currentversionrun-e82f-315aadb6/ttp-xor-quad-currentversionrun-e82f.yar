rule TTP_XOR_QUAD_CurrentVersionRun_e82f {
  strings:
    $key_e82f = { bb 40 [2] 9f 4e [2] b4 62 [2] 9a 40 [2] 8e 5b [2] 81 41 [2] 9f 5c [2] 9d 5d [2] 86 5b [2] 9a 5c [2] 86 73 }

  condition:
    any of them
}