rule TTP_XOR_QUAD_CurrentVersionRun_e420 {
  strings:
    $key_e420 = { b7 4f [2] 93 41 [2] b8 6d [2] 96 4f [2] 82 54 [2] 8d 4e [2] 93 53 [2] 91 52 [2] 8a 54 [2] 96 53 [2] 8a 7c }

  condition:
    any of them
}