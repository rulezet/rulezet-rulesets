rule TTP_XOR_QUAD_CurrentVersionRun_ca05 {
  strings:
    $key_ca05 = { 99 6a [2] bd 64 [2] 96 48 [2] b8 6a [2] ac 71 [2] a3 6b [2] bd 76 [2] bf 77 [2] a4 71 [2] b8 76 [2] a4 59 }

  condition:
    any of them
}