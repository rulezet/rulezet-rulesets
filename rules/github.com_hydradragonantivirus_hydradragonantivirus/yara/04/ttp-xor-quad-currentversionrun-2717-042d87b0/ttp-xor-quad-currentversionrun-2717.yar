rule TTP_XOR_QUAD_CurrentVersionRun_2717 {
  strings:
    $key_2717 = { 74 78 [2] 50 76 [2] 7b 5a [2] 55 78 [2] 41 63 [2] 4e 79 [2] 50 64 [2] 52 65 [2] 49 63 [2] 55 64 [2] 49 4b }

  condition:
    any of them
}