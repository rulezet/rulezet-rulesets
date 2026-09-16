rule TTP_XOR_QUAD_CurrentVersionRun_dcf2 {
  strings:
    $key_dcf2 = { 8f 9d [2] ab 93 [2] 80 bf [2] ae 9d [2] ba 86 [2] b5 9c [2] ab 81 [2] a9 80 [2] b2 86 [2] ae 81 [2] b2 ae }

  condition:
    any of them
}