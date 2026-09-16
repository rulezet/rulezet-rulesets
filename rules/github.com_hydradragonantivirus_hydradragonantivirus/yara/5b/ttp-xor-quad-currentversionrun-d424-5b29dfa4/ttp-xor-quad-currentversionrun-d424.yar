rule TTP_XOR_QUAD_CurrentVersionRun_d424 {
  strings:
    $key_d424 = { 87 4b [2] a3 45 [2] 88 69 [2] a6 4b [2] b2 50 [2] bd 4a [2] a3 57 [2] a1 56 [2] ba 50 [2] a6 57 [2] ba 78 }

  condition:
    any of them
}