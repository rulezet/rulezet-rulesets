rule TTP_XOR_QUAD_CurrentVersionRun_db4a {
  strings:
    $key_db4a = { 88 25 [2] ac 2b [2] 87 07 [2] a9 25 [2] bd 3e [2] b2 24 [2] ac 39 [2] ae 38 [2] b5 3e [2] a9 39 [2] b5 16 }

  condition:
    any of them
}