rule TTP_XOR_QUAD_CurrentVersionRun_3926 {
  strings:
    $key_3926 = { 6a 49 [2] 4e 47 [2] 65 6b [2] 4b 49 [2] 5f 52 [2] 50 48 [2] 4e 55 [2] 4c 54 [2] 57 52 [2] 4b 55 [2] 57 7a }

  condition:
    any of them
}