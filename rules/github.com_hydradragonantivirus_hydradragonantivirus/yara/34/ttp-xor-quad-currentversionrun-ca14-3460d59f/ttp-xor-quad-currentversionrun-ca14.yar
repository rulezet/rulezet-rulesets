rule TTP_XOR_QUAD_CurrentVersionRun_ca14 {
  strings:
    $key_ca14 = { 99 7b [2] bd 75 [2] 96 59 [2] b8 7b [2] ac 60 [2] a3 7a [2] bd 67 [2] bf 66 [2] a4 60 [2] b8 67 [2] a4 48 }

  condition:
    any of them
}