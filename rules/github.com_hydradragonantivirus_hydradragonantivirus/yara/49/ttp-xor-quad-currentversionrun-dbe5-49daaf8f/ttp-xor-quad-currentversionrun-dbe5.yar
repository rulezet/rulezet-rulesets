rule TTP_XOR_QUAD_CurrentVersionRun_dbe5 {
  strings:
    $key_dbe5 = { 88 8a [2] ac 84 [2] 87 a8 [2] a9 8a [2] bd 91 [2] b2 8b [2] ac 96 [2] ae 97 [2] b5 91 [2] a9 96 [2] b5 b9 }

  condition:
    any of them
}