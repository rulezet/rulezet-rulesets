rule TTP_XOR_QUAD_CurrentVersionRun_2ef2 {
  strings:
    $key_2ef2 = { 7d 9d [2] 59 93 [2] 72 bf [2] 5c 9d [2] 48 86 [2] 47 9c [2] 59 81 [2] 5b 80 [2] 40 86 [2] 5c 81 [2] 40 ae }

  condition:
    any of them
}