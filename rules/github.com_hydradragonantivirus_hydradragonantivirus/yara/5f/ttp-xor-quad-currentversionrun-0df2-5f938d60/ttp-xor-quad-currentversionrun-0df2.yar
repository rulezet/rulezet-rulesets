rule TTP_XOR_QUAD_CurrentVersionRun_0df2 {
  strings:
    $key_0df2 = { 5e 9d [2] 7a 93 [2] 51 bf [2] 7f 9d [2] 6b 86 [2] 64 9c [2] 7a 81 [2] 78 80 [2] 63 86 [2] 7f 81 [2] 63 ae }

  condition:
    any of them
}