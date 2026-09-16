rule TTP_XOR_QUAD_CurrentVersionRun_6217 {
  strings:
    $key_6217 = { 31 78 [2] 15 76 [2] 3e 5a [2] 10 78 [2] 04 63 [2] 0b 79 [2] 15 64 [2] 17 65 [2] 0c 63 [2] 10 64 [2] 0c 4b }

  condition:
    any of them
}