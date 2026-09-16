rule TTP_XOR_QUAD_CurrentVersionRun_e67d {
  strings:
    $key_e67d = { b5 12 [2] 91 1c [2] ba 30 [2] 94 12 [2] 80 09 [2] 8f 13 [2] 91 0e [2] 93 0f [2] 88 09 [2] 94 0e [2] 88 21 }

  condition:
    any of them
}