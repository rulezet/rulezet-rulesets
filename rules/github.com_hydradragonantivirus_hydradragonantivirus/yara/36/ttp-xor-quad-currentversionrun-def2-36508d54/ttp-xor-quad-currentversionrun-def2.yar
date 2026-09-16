rule TTP_XOR_QUAD_CurrentVersionRun_def2 {
  strings:
    $key_def2 = { 8d 9d [2] a9 93 [2] 82 bf [2] ac 9d [2] b8 86 [2] b7 9c [2] a9 81 [2] ab 80 [2] b0 86 [2] ac 81 [2] b0 ae }

  condition:
    any of them
}