rule TTP_XOR_QUAD_CurrentVersionRun_e67c {
  strings:
    $key_e67c = { b5 13 [2] 91 1d [2] ba 31 [2] 94 13 [2] 80 08 [2] 8f 12 [2] 91 0f [2] 93 0e [2] 88 08 [2] 94 0f [2] 88 20 }

  condition:
    any of them
}