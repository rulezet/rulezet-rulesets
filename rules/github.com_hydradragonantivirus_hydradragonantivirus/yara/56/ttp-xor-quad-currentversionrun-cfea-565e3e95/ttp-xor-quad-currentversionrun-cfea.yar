rule TTP_XOR_QUAD_CurrentVersionRun_cfea {
  strings:
    $key_cfea = { 9c 85 [2] b8 8b [2] 93 a7 [2] bd 85 [2] a9 9e [2] a6 84 [2] b8 99 [2] ba 98 [2] a1 9e [2] bd 99 [2] a1 b6 }

  condition:
    any of them
}