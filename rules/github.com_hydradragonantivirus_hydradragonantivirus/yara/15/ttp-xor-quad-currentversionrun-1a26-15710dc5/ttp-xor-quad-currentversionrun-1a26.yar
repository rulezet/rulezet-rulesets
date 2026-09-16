rule TTP_XOR_QUAD_CurrentVersionRun_1a26 {
  strings:
    $key_1a26 = { 49 49 [2] 6d 47 [2] 46 6b [2] 68 49 [2] 7c 52 [2] 73 48 [2] 6d 55 [2] 6f 54 [2] 74 52 [2] 68 55 [2] 74 7a }

  condition:
    any of them
}