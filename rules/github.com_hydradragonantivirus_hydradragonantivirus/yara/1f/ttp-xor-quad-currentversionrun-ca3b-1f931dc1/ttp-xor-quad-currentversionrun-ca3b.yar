rule TTP_XOR_QUAD_CurrentVersionRun_ca3b {
  strings:
    $key_ca3b = { 99 54 [2] bd 5a [2] 96 76 [2] b8 54 [2] ac 4f [2] a3 55 [2] bd 48 [2] bf 49 [2] a4 4f [2] b8 48 [2] a4 67 }

  condition:
    any of them
}