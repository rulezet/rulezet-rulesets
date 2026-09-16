rule TTP_XOR_QUAD_CurrentVersionRun_d350 {
  strings:
    $key_d350 = { 80 3f [2] a4 31 [2] 8f 1d [2] a1 3f [2] b5 24 [2] ba 3e [2] a4 23 [2] a6 22 [2] bd 24 [2] a1 23 [2] bd 0c }

  condition:
    any of them
}