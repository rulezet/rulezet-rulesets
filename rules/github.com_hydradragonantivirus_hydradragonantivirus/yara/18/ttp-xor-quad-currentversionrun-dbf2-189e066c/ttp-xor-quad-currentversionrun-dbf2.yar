rule TTP_XOR_QUAD_CurrentVersionRun_dbf2 {
  strings:
    $key_dbf2 = { 88 9d [2] ac 93 [2] 87 bf [2] a9 9d [2] bd 86 [2] b2 9c [2] ac 81 [2] ae 80 [2] b5 86 [2] a9 81 [2] b5 ae }

  condition:
    any of them
}