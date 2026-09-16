rule TTP_XOR_QUAD_CurrentVersionRun_e517 {
  strings:
    $key_e517 = { b6 78 [2] 92 76 [2] b9 5a [2] 97 78 [2] 83 63 [2] 8c 79 [2] 92 64 [2] 90 65 [2] 8b 63 [2] 97 64 [2] 8b 4b }

  condition:
    any of them
}