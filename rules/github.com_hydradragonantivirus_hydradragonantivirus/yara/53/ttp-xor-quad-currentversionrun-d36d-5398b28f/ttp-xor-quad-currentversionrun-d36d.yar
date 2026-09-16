rule TTP_XOR_QUAD_CurrentVersionRun_d36d {
  strings:
    $key_d36d = { 80 02 [2] a4 0c [2] 8f 20 [2] a1 02 [2] b5 19 [2] ba 03 [2] a4 1e [2] a6 1f [2] bd 19 [2] a1 1e [2] bd 31 }

  condition:
    any of them
}