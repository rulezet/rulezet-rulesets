rule TTP_XOR_QUAD_CurrentVersionRun_2cf2 {
  strings:
    $key_2cf2 = { 7f 9d [2] 5b 93 [2] 70 bf [2] 5e 9d [2] 4a 86 [2] 45 9c [2] 5b 81 [2] 59 80 [2] 42 86 [2] 5e 81 [2] 42 ae }

  condition:
    any of them
}