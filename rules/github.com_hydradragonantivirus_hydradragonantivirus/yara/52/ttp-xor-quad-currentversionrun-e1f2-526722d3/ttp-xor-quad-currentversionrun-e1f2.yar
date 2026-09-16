rule TTP_XOR_QUAD_CurrentVersionRun_e1f2 {
  strings:
    $key_e1f2 = { b2 9d [2] 96 93 [2] bd bf [2] 93 9d [2] 87 86 [2] 88 9c [2] 96 81 [2] 94 80 [2] 8f 86 [2] 93 81 [2] 8f ae }

  condition:
    any of them
}