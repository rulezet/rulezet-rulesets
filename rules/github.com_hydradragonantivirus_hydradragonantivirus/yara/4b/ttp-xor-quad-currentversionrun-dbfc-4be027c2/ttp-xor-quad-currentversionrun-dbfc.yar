rule TTP_XOR_QUAD_CurrentVersionRun_dbfc {
  strings:
    $key_dbfc = { 88 93 [2] ac 9d [2] 87 b1 [2] a9 93 [2] bd 88 [2] b2 92 [2] ac 8f [2] ae 8e [2] b5 88 [2] a9 8f [2] b5 a0 }

  condition:
    any of them
}