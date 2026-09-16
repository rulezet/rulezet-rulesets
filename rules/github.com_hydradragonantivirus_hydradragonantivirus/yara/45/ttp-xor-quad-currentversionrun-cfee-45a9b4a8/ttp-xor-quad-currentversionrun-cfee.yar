rule TTP_XOR_QUAD_CurrentVersionRun_cfee {
  strings:
    $key_cfee = { 9c 81 [2] b8 8f [2] 93 a3 [2] bd 81 [2] a9 9a [2] a6 80 [2] b8 9d [2] ba 9c [2] a1 9a [2] bd 9d [2] a1 b2 }

  condition:
    any of them
}