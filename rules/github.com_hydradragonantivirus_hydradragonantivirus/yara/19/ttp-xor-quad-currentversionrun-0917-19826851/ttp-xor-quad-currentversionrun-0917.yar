rule TTP_XOR_QUAD_CurrentVersionRun_0917 {
  strings:
    $key_0917 = { 5a 78 [2] 7e 76 [2] 55 5a [2] 7b 78 [2] 6f 63 [2] 60 79 [2] 7e 64 [2] 7c 65 [2] 67 63 [2] 7b 64 [2] 67 4b }

  condition:
    any of them
}