rule TTP_XOR_QUAD_CurrentVersionRun_f8f2 {
  strings:
    $key_f8f2 = { ab 9d [2] 8f 93 [2] a4 bf [2] 8a 9d [2] 9e 86 [2] 91 9c [2] 8f 81 [2] 8d 80 [2] 96 86 [2] 8a 81 [2] 96 ae }

  condition:
    any of them
}