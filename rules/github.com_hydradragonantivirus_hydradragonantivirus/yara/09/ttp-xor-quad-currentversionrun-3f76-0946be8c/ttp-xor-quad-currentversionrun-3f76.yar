rule TTP_XOR_QUAD_CurrentVersionRun_3f76 {
  strings:
    $key_3f76 = { 6c 19 [2] 48 17 [2] 63 3b [2] 4d 19 [2] 59 02 [2] 56 18 [2] 48 05 [2] 4a 04 [2] 51 02 [2] 4d 05 [2] 51 2a }

  condition:
    any of them
}