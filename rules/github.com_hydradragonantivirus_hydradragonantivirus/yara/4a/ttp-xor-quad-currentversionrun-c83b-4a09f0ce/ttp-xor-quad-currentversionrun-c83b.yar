rule TTP_XOR_QUAD_CurrentVersionRun_c83b {
  strings:
    $key_c83b = { 9b 54 [2] bf 5a [2] 94 76 [2] ba 54 [2] ae 4f [2] a1 55 [2] bf 48 [2] bd 49 [2] a6 4f [2] ba 48 [2] a6 67 }

  condition:
    any of them
}