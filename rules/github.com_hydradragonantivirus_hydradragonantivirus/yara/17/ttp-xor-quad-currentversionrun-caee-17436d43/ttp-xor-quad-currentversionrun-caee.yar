rule TTP_XOR_QUAD_CurrentVersionRun_caee {
  strings:
    $key_caee = { 99 81 [2] bd 8f [2] 96 a3 [2] b8 81 [2] ac 9a [2] a3 80 [2] bd 9d [2] bf 9c [2] a4 9a [2] b8 9d [2] a4 b2 }

  condition:
    any of them
}