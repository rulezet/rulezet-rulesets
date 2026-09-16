rule TTP_XOR_QUAD_CurrentVersionRun_6f12 {
  strings:
    $key_6f12 = { 3c 7d [2] 18 73 [2] 33 5f [2] 1d 7d [2] 09 66 [2] 06 7c [2] 18 61 [2] 1a 60 [2] 01 66 [2] 1d 61 [2] 01 4e }

  condition:
    any of them
}