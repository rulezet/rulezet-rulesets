rule TTP_XOR_QUAD_CurrentVersionRun_7e76 {
  strings:
    $key_7e76 = { 2d 19 [2] 09 17 [2] 22 3b [2] 0c 19 [2] 18 02 [2] 17 18 [2] 09 05 [2] 0b 04 [2] 10 02 [2] 0c 05 [2] 10 2a }

  condition:
    any of them
}