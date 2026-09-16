rule TTP_XOR_QUAD_CurrentVersionRun_5578 {
  strings:
    $key_5578 = { 06 17 [2] 22 19 [2] 09 35 [2] 27 17 [2] 33 0c [2] 3c 16 [2] 22 0b [2] 20 0a [2] 3b 0c [2] 27 0b [2] 3b 24 }

  condition:
    any of them
}