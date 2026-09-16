rule TTP_XOR_QUAD_CurrentVersionRun_caec {
  strings:
    $key_caec = { 99 83 [2] bd 8d [2] 96 a1 [2] b8 83 [2] ac 98 [2] a3 82 [2] bd 9f [2] bf 9e [2] a4 98 [2] b8 9f [2] a4 b0 }

  condition:
    any of them
}