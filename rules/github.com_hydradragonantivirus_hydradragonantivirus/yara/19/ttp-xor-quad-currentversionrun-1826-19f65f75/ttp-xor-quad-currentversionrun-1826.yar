rule TTP_XOR_QUAD_CurrentVersionRun_1826 {
  strings:
    $key_1826 = { 4b 49 [2] 6f 47 [2] 44 6b [2] 6a 49 [2] 7e 52 [2] 71 48 [2] 6f 55 [2] 6d 54 [2] 76 52 [2] 6a 55 [2] 76 7a }

  condition:
    any of them
}