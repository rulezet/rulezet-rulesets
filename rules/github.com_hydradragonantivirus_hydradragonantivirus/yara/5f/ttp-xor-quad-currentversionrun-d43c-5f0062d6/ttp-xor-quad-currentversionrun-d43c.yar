rule TTP_XOR_QUAD_CurrentVersionRun_d43c {
  strings:
    $key_d43c = { 87 53 [2] a3 5d [2] 88 71 [2] a6 53 [2] b2 48 [2] bd 52 [2] a3 4f [2] a1 4e [2] ba 48 [2] a6 4f [2] ba 60 }

  condition:
    any of them
}