rule TTP_XOR_QUAD_CurrentVersionRun_c5f2 {
  strings:
    $key_c5f2 = { 96 9d [2] b2 93 [2] 99 bf [2] b7 9d [2] a3 86 [2] ac 9c [2] b2 81 [2] b0 80 [2] ab 86 [2] b7 81 [2] ab ae }

  condition:
    any of them
}