rule TTP_XOR_QUAD_CurrentVersionRun_e67a {
  strings:
    $key_e67a = { b5 15 [2] 91 1b [2] ba 37 [2] 94 15 [2] 80 0e [2] 8f 14 [2] 91 09 [2] 93 08 [2] 88 0e [2] 94 09 [2] 88 26 }

  condition:
    any of them
}