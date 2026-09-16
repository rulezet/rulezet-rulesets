rule TTP_XOR_QUAD_CurrentVersionRun_e61f {
  strings:
    $key_e61f = { b5 70 [2] 91 7e [2] ba 52 [2] 94 70 [2] 80 6b [2] 8f 71 [2] 91 6c [2] 93 6d [2] 88 6b [2] 94 6c [2] 88 43 }

  condition:
    any of them
}