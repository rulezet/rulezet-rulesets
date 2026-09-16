rule TTP_XOR_QUAD_CurrentVersionRun_e800 {
  strings:
    $key_e800 = { bb 6f [2] 9f 61 [2] b4 4d [2] 9a 6f [2] 8e 74 [2] 81 6e [2] 9f 73 [2] 9d 72 [2] 86 74 [2] 9a 73 [2] 86 5c }

  condition:
    any of them
}