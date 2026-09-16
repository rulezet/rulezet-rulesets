rule TTP_XOR_QUAD_CurrentVersionRun_3a26 {
  strings:
    $key_3a26 = { 69 49 [2] 4d 47 [2] 66 6b [2] 48 49 [2] 5c 52 [2] 53 48 [2] 4d 55 [2] 4f 54 [2] 54 52 [2] 48 55 [2] 54 7a }

  condition:
    any of them
}