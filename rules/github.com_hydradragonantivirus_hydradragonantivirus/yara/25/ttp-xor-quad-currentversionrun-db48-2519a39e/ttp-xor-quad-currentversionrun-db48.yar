rule TTP_XOR_QUAD_CurrentVersionRun_db48 {
  strings:
    $key_db48 = { 88 27 [2] ac 29 [2] 87 05 [2] a9 27 [2] bd 3c [2] b2 26 [2] ac 3b [2] ae 3a [2] b5 3c [2] a9 3b [2] b5 14 }

  condition:
    any of them
}