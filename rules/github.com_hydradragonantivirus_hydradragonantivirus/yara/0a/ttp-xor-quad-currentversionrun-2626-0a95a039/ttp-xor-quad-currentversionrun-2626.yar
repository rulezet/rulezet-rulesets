rule TTP_XOR_QUAD_CurrentVersionRun_2626 {
  strings:
    $key_2626 = { 75 49 [2] 51 47 [2] 7a 6b [2] 54 49 [2] 40 52 [2] 4f 48 [2] 51 55 [2] 53 54 [2] 48 52 [2] 54 55 [2] 48 7a }

  condition:
    any of them
}