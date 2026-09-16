rule TTP_XOR_QUAD_CurrentVersionRun_c8f0 {
  strings:
    $key_c8f0 = { 9b 9f [2] bf 91 [2] 94 bd [2] ba 9f [2] ae 84 [2] a1 9e [2] bf 83 [2] bd 82 [2] a6 84 [2] ba 83 [2] a6 ac }

  condition:
    any of them
}