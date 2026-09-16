rule TTP_XOR_QUAD_CurrentVersionRun_cae8 {
  strings:
    $key_cae8 = { 99 87 [2] bd 89 [2] 96 a5 [2] b8 87 [2] ac 9c [2] a3 86 [2] bd 9b [2] bf 9a [2] a4 9c [2] b8 9b [2] a4 b4 }

  condition:
    any of them
}