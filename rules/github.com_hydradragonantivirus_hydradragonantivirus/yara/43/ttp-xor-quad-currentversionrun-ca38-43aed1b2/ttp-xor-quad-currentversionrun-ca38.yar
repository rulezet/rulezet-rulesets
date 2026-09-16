rule TTP_XOR_QUAD_CurrentVersionRun_ca38 {
  strings:
    $key_ca38 = { 99 57 [2] bd 59 [2] 96 75 [2] b8 57 [2] ac 4c [2] a3 56 [2] bd 4b [2] bf 4a [2] a4 4c [2] b8 4b [2] a4 64 }

  condition:
    any of them
}