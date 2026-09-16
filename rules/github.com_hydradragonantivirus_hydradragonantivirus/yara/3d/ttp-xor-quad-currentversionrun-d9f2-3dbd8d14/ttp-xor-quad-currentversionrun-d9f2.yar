rule TTP_XOR_QUAD_CurrentVersionRun_d9f2 {
  strings:
    $key_d9f2 = { 8a 9d [2] ae 93 [2] 85 bf [2] ab 9d [2] bf 86 [2] b0 9c [2] ae 81 [2] ac 80 [2] b7 86 [2] ab 81 [2] b7 ae }

  condition:
    any of them
}