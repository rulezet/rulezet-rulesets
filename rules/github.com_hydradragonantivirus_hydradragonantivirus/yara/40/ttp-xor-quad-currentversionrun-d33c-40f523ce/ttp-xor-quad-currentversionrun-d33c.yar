rule TTP_XOR_QUAD_CurrentVersionRun_d33c {
  strings:
    $key_d33c = { 80 53 [2] a4 5d [2] 8f 71 [2] a1 53 [2] b5 48 [2] ba 52 [2] a4 4f [2] a6 4e [2] bd 48 [2] a1 4f [2] bd 60 }

  condition:
    any of them
}