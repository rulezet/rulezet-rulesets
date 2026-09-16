rule TTP_XOR_QUAD_CurrentVersionRun_db05 {
  strings:
    $key_db05 = { 88 6a [2] ac 64 [2] 87 48 [2] a9 6a [2] bd 71 [2] b2 6b [2] ac 76 [2] ae 77 [2] b5 71 [2] a9 76 [2] b5 59 }

  condition:
    any of them
}