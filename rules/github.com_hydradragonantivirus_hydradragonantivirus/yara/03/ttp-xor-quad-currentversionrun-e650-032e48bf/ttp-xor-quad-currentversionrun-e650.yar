rule TTP_XOR_QUAD_CurrentVersionRun_e650 {
  strings:
    $key_e650 = { b5 3f [2] 91 31 [2] ba 1d [2] 94 3f [2] 80 24 [2] 8f 3e [2] 91 23 [2] 93 22 [2] 88 24 [2] 94 23 [2] 88 0c }

  condition:
    any of them
}