rule TTP_XOR_QUAD_CurrentVersionRun_db09 {
  strings:
    $key_db09 = { 88 66 [2] ac 68 [2] 87 44 [2] a9 66 [2] bd 7d [2] b2 67 [2] ac 7a [2] ae 7b [2] b5 7d [2] a9 7a [2] b5 55 }

  condition:
    any of them
}