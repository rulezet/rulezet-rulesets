rule TTP_XOR_QUAD_CurrentVersionRun_db5e {
  strings:
    $key_db5e = { 88 31 [2] ac 3f [2] 87 13 [2] a9 31 [2] bd 2a [2] b2 30 [2] ac 2d [2] ae 2c [2] b5 2a [2] a9 2d [2] b5 02 }

  condition:
    any of them
}