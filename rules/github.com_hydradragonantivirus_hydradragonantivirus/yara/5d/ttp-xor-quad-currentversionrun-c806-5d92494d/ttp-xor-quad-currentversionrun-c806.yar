rule TTP_XOR_QUAD_CurrentVersionRun_c806 {
  strings:
    $key_c806 = { 9b 69 [2] bf 67 [2] 94 4b [2] ba 69 [2] ae 72 [2] a1 68 [2] bf 75 [2] bd 74 [2] a6 72 [2] ba 75 [2] a6 5a }

  condition:
    any of them
}