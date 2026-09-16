rule TTP_XOR_QUAD_CurrentVersionRun_3a76 {
  strings:
    $key_3a76 = { 69 19 [2] 4d 17 [2] 66 3b [2] 48 19 [2] 5c 02 [2] 53 18 [2] 4d 05 [2] 4f 04 [2] 54 02 [2] 48 05 [2] 54 2a }

  condition:
    any of them
}