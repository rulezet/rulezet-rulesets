rule TTP_XOR_QUAD_CurrentVersionRun_5726 {
  strings:
    $key_5726 = { 04 49 [2] 20 47 [2] 0b 6b [2] 25 49 [2] 31 52 [2] 3e 48 [2] 20 55 [2] 22 54 [2] 39 52 [2] 25 55 [2] 39 7a }

  condition:
    any of them
}