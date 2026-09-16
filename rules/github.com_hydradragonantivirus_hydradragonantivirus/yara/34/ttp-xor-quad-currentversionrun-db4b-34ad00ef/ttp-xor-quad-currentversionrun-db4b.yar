rule TTP_XOR_QUAD_CurrentVersionRun_db4b {
  strings:
    $key_db4b = { 88 24 [2] ac 2a [2] 87 06 [2] a9 24 [2] bd 3f [2] b2 25 [2] ac 38 [2] ae 39 [2] b5 3f [2] a9 38 [2] b5 17 }

  condition:
    any of them
}