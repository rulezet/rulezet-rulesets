rule TTP_XOR_QUAD_CurrentVersionRun_d33d {
  strings:
    $key_d33d = { 80 52 [2] a4 5c [2] 8f 70 [2] a1 52 [2] b5 49 [2] ba 53 [2] a4 4e [2] a6 4f [2] bd 49 [2] a1 4e [2] bd 61 }

  condition:
    any of them
}