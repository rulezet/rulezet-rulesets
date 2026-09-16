rule TTP_XOR_QUAD_CurrentVersionRun_d31f {
  strings:
    $key_d31f = { 80 70 [2] a4 7e [2] 8f 52 [2] a1 70 [2] b5 6b [2] ba 71 [2] a4 6c [2] a6 6d [2] bd 6b [2] a1 6c [2] bd 43 }

  condition:
    any of them
}