rule TTP_XOR_QUAD_CurrentVersionRun_e81c {
  strings:
    $key_e81c = { bb 73 [2] 9f 7d [2] b4 51 [2] 9a 73 [2] 8e 68 [2] 81 72 [2] 9f 6f [2] 9d 6e [2] 86 68 [2] 9a 6f [2] 86 40 }

  condition:
    any of them
}