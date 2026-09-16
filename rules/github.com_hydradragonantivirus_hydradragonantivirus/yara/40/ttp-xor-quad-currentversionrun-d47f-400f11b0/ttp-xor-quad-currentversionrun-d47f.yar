rule TTP_XOR_QUAD_CurrentVersionRun_d47f {
  strings:
    $key_d47f = { 87 10 [2] a3 1e [2] 88 32 [2] a6 10 [2] b2 0b [2] bd 11 [2] a3 0c [2] a1 0d [2] ba 0b [2] a6 0c [2] ba 23 }

  condition:
    any of them
}