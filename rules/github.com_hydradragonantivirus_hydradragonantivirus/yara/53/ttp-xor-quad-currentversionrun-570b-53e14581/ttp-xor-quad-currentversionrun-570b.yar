rule TTP_XOR_QUAD_CurrentVersionRun_570b {
  strings:
    $key_570b = { 04 64 [2] 20 6a [2] 0b 46 [2] 25 64 [2] 31 7f [2] 3e 65 [2] 20 78 [2] 22 79 [2] 39 7f [2] 25 78 [2] 39 57 }

  condition:
    any of them
}