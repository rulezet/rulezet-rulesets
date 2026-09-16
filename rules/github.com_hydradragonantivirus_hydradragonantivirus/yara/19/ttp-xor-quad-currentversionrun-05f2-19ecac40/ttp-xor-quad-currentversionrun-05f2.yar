rule TTP_XOR_QUAD_CurrentVersionRun_05f2 {
  strings:
    $key_05f2 = { 56 9d [2] 72 93 [2] 59 bf [2] 77 9d [2] 63 86 [2] 6c 9c [2] 72 81 [2] 70 80 [2] 6b 86 [2] 77 81 [2] 6b ae }

  condition:
    any of them
}