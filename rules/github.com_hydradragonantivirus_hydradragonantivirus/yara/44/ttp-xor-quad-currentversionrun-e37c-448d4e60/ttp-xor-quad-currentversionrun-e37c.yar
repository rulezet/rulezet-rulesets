rule TTP_XOR_QUAD_CurrentVersionRun_e37c {
  strings:
    $key_e37c = { b0 13 [2] 94 1d [2] bf 31 [2] 91 13 [2] 85 08 [2] 8a 12 [2] 94 0f [2] 96 0e [2] 8d 08 [2] 91 0f [2] 8d 20 }

  condition:
    any of them
}