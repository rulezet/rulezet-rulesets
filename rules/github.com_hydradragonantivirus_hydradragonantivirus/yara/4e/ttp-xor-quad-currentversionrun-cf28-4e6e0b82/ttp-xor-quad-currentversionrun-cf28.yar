rule TTP_XOR_QUAD_CurrentVersionRun_cf28 {
  strings:
    $key_cf28 = { 9c 47 [2] b8 49 [2] 93 65 [2] bd 47 [2] a9 5c [2] a6 46 [2] b8 5b [2] ba 5a [2] a1 5c [2] bd 5b [2] a1 74 }

  condition:
    any of them
}