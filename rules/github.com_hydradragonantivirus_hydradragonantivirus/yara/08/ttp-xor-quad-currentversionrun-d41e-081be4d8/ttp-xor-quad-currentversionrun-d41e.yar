rule TTP_XOR_QUAD_CurrentVersionRun_d41e {
  strings:
    $key_d41e = { 87 71 [2] a3 7f [2] 88 53 [2] a6 71 [2] b2 6a [2] bd 70 [2] a3 6d [2] a1 6c [2] ba 6a [2] a6 6d [2] ba 42 }

  condition:
    any of them
}