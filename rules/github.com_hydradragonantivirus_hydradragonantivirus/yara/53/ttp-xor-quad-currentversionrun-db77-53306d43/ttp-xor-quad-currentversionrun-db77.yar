rule TTP_XOR_QUAD_CurrentVersionRun_db77 {
  strings:
    $key_db77 = { 88 18 [2] ac 16 [2] 87 3a [2] a9 18 [2] bd 03 [2] b2 19 [2] ac 04 [2] ae 05 [2] b5 03 [2] a9 04 [2] b5 2b }

  condition:
    any of them
}