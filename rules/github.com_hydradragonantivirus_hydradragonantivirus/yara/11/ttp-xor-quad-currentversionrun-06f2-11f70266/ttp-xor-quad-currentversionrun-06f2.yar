rule TTP_XOR_QUAD_CurrentVersionRun_06f2 {
  strings:
    $key_06f2 = { 55 9d [2] 71 93 [2] 5a bf [2] 74 9d [2] 60 86 [2] 6f 9c [2] 71 81 [2] 73 80 [2] 68 86 [2] 74 81 [2] 68 ae }

  condition:
    any of them
}