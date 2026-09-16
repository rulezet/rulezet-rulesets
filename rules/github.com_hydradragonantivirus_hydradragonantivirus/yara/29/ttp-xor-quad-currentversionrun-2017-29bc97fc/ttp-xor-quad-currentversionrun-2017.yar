rule TTP_XOR_QUAD_CurrentVersionRun_2017 {
  strings:
    $key_2017 = { 73 78 [2] 57 76 [2] 7c 5a [2] 52 78 [2] 46 63 [2] 49 79 [2] 57 64 [2] 55 65 [2] 4e 63 [2] 52 64 [2] 4e 4b }

  condition:
    any of them
}