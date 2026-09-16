rule TTP_XOR_QUAD_CurrentVersionRun_e61e {
  strings:
    $key_e61e = { b5 71 [2] 91 7f [2] ba 53 [2] 94 71 [2] 80 6a [2] 8f 70 [2] 91 6d [2] 93 6c [2] 88 6a [2] 94 6d [2] 88 42 }

  condition:
    any of them
}