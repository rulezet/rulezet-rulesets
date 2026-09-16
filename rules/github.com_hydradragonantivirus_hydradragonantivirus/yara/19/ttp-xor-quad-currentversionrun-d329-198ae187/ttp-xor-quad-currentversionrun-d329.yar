rule TTP_XOR_QUAD_CurrentVersionRun_d329 {
  strings:
    $key_d329 = { 80 46 [2] a4 48 [2] 8f 64 [2] a1 46 [2] b5 5d [2] ba 47 [2] a4 5a [2] a6 5b [2] bd 5d [2] a1 5a [2] bd 75 }

  condition:
    any of them
}