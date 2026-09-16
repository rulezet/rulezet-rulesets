rule TTP_XOR_QUAD_CurrentVersionRun_db26 {
  strings:
    $key_db26 = { 88 49 [2] ac 47 [2] 87 6b [2] a9 49 [2] bd 52 [2] b2 48 [2] ac 55 [2] ae 54 [2] b5 52 [2] a9 55 [2] b5 7a }

  condition:
    any of them
}