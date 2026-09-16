rule TTP_XOR_QUAD_CurrentVersionRun_e61d {
  strings:
    $key_e61d = { b5 72 [2] 91 7c [2] ba 50 [2] 94 72 [2] 80 69 [2] 8f 73 [2] 91 6e [2] 93 6f [2] 88 69 [2] 94 6e [2] 88 41 }

  condition:
    any of them
}