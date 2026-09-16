rule TTP_XOR_QUAD_CurrentVersionRun_cfe2 {
  strings:
    $key_cfe2 = { 9c 8d [2] b8 83 [2] 93 af [2] bd 8d [2] a9 96 [2] a6 8c [2] b8 91 [2] ba 90 [2] a1 96 [2] bd 91 [2] a1 be }

  condition:
    any of them
}