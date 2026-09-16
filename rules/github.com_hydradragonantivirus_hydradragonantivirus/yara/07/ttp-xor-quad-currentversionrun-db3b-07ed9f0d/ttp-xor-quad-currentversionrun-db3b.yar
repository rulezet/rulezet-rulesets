rule TTP_XOR_QUAD_CurrentVersionRun_db3b {
  strings:
    $key_db3b = { 88 54 [2] ac 5a [2] 87 76 [2] a9 54 [2] bd 4f [2] b2 55 [2] ac 48 [2] ae 49 [2] b5 4f [2] a9 48 [2] b5 67 }

  condition:
    any of them
}