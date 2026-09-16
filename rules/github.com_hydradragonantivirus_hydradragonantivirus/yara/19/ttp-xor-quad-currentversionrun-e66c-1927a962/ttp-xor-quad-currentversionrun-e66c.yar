rule TTP_XOR_QUAD_CurrentVersionRun_e66c {
  strings:
    $key_e66c = { b5 03 [2] 91 0d [2] ba 21 [2] 94 03 [2] 80 18 [2] 8f 02 [2] 91 1f [2] 93 1e [2] 88 18 [2] 94 1f [2] 88 30 }

  condition:
    any of them
}