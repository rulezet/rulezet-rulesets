rule TTP_XOR_QUAD_CurrentVersionRun_ca26 {
  strings:
    $key_ca26 = { 99 49 [2] bd 47 [2] 96 6b [2] b8 49 [2] ac 52 [2] a3 48 [2] bd 55 [2] bf 54 [2] a4 52 [2] b8 55 [2] a4 7a }

  condition:
    any of them
}