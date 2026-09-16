rule TTP_XOR_QUAD_CurrentVersionRun_d376 {
  strings:
    $key_d376 = { 80 19 [2] a4 17 [2] 8f 3b [2] a1 19 [2] b5 02 [2] ba 18 [2] a4 05 [2] a6 04 [2] bd 02 [2] a1 05 [2] bd 2a }

  condition:
    any of them
}