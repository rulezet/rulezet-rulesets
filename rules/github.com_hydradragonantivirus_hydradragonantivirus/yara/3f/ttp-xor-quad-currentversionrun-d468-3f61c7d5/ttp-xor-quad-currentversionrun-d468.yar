rule TTP_XOR_QUAD_CurrentVersionRun_d468 {
  strings:
    $key_d468 = { 87 07 [2] a3 09 [2] 88 25 [2] a6 07 [2] b2 1c [2] bd 06 [2] a3 1b [2] a1 1a [2] ba 1c [2] a6 1b [2] ba 34 }

  condition:
    any of them
}