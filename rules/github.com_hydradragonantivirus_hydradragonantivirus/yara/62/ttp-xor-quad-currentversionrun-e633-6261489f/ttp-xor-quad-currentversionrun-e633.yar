rule TTP_XOR_QUAD_CurrentVersionRun_e633 {
  strings:
    $key_e633 = { b5 5c [2] 91 52 [2] ba 7e [2] 94 5c [2] 80 47 [2] 8f 5d [2] 91 40 [2] 93 41 [2] 88 47 [2] 94 40 [2] 88 6f }

  condition:
    any of them
}