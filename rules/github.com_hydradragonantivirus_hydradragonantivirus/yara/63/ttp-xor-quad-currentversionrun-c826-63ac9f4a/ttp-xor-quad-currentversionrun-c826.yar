rule TTP_XOR_QUAD_CurrentVersionRun_c826 {
  strings:
    $key_c826 = { 9b 49 [2] bf 47 [2] 94 6b [2] ba 49 [2] ae 52 [2] a1 48 [2] bf 55 [2] bd 54 [2] a6 52 [2] ba 55 [2] a6 7a }

  condition:
    any of them
}