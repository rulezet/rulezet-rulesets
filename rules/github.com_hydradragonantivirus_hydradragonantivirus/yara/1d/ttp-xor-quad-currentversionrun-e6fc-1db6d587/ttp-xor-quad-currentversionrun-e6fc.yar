rule TTP_XOR_QUAD_CurrentVersionRun_e6fc {
  strings:
    $key_e6fc = { b5 93 [2] 91 9d [2] ba b1 [2] 94 93 [2] 80 88 [2] 8f 92 [2] 91 8f [2] 93 8e [2] 88 88 [2] 94 8f [2] 88 a0 }

  condition:
    any of them
}