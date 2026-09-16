rule TTP_XOR_QUAD_CurrentVersionRun_dbef {
  strings:
    $key_dbef = { 88 80 [2] ac 8e [2] 87 a2 [2] a9 80 [2] bd 9b [2] b2 81 [2] ac 9c [2] ae 9d [2] b5 9b [2] a9 9c [2] b5 b3 }

  condition:
    any of them
}