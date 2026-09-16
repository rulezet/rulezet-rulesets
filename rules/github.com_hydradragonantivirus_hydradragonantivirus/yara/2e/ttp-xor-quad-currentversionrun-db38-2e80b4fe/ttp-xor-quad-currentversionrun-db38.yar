rule TTP_XOR_QUAD_CurrentVersionRun_db38 {
  strings:
    $key_db38 = { 88 57 [2] ac 59 [2] 87 75 [2] a9 57 [2] bd 4c [2] b2 56 [2] ac 4b [2] ae 4a [2] b5 4c [2] a9 4b [2] b5 64 }

  condition:
    any of them
}