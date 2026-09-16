rule TTP_XOR_QUAD_CurrentVersionRun_e64d {
  strings:
    $key_e64d = { b5 22 [2] 91 2c [2] ba 00 [2] 94 22 [2] 80 39 [2] 8f 23 [2] 91 3e [2] 93 3f [2] 88 39 [2] 94 3e [2] 88 11 }

  condition:
    any of them
}