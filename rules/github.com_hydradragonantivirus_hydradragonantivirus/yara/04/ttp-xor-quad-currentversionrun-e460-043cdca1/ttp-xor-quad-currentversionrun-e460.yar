rule TTP_XOR_QUAD_CurrentVersionRun_e460 {
  strings:
    $key_e460 = { b7 0f [2] 93 01 [2] b8 2d [2] 96 0f [2] 82 14 [2] 8d 0e [2] 93 13 [2] 91 12 [2] 8a 14 [2] 96 13 [2] 8a 3c }

  condition:
    any of them
}