rule TTP_XOR_QUAD_CurrentVersionRun_f9f2 {
  strings:
    $key_f9f2 = { aa 9d [2] 8e 93 [2] a5 bf [2] 8b 9d [2] 9f 86 [2] 90 9c [2] 8e 81 [2] 8c 80 [2] 97 86 [2] 8b 81 [2] 97 ae }

  condition:
    any of them
}