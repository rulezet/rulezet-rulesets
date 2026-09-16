rule TTP_XOR_QUAD_CurrentVersionRun_e81d {
  strings:
    $key_e81d = { bb 72 [2] 9f 7c [2] b4 50 [2] 9a 72 [2] 8e 69 [2] 81 73 [2] 9f 6e [2] 9d 6f [2] 86 69 [2] 9a 6e [2] 86 41 }

  condition:
    any of them
}