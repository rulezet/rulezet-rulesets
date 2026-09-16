rule TTP_XOR_QUAD_CurrentVersionRun_e46c {
  strings:
    $key_e46c = { b7 03 [2] 93 0d [2] b8 21 [2] 96 03 [2] 82 18 [2] 8d 02 [2] 93 1f [2] 91 1e [2] 8a 18 [2] 96 1f [2] 8a 30 }

  condition:
    any of them
}