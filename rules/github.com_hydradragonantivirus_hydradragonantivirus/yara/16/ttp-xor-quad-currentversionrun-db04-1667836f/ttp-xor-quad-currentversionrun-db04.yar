rule TTP_XOR_QUAD_CurrentVersionRun_db04 {
  strings:
    $key_db04 = { 88 6b [2] ac 65 [2] 87 49 [2] a9 6b [2] bd 70 [2] b2 6a [2] ac 77 [2] ae 76 [2] b5 70 [2] a9 77 [2] b5 58 }

  condition:
    any of them
}