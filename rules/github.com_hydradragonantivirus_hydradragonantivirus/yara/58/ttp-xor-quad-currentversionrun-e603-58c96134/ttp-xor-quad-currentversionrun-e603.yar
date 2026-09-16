rule TTP_XOR_QUAD_CurrentVersionRun_e603 {
  strings:
    $key_e603 = { b5 6c [2] 91 62 [2] ba 4e [2] 94 6c [2] 80 77 [2] 8f 6d [2] 91 70 [2] 93 71 [2] 88 77 [2] 94 70 [2] 88 5f }

  condition:
    any of them
}