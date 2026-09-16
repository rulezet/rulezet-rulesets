rule TTP_XOR_QUAD_CurrentVersionRun_627b {
  strings:
    $key_627b = { 31 14 [2] 15 1a [2] 3e 36 [2] 10 14 [2] 04 0f [2] 0b 15 [2] 15 08 [2] 17 09 [2] 0c 0f [2] 10 08 [2] 0c 27 }

  condition:
    any of them
}