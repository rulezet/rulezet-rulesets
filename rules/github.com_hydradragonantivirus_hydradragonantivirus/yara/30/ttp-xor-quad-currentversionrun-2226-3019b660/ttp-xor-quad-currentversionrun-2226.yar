rule TTP_XOR_QUAD_CurrentVersionRun_2226 {
  strings:
    $key_2226 = { 71 49 [2] 55 47 [2] 7e 6b [2] 50 49 [2] 44 52 [2] 4b 48 [2] 55 55 [2] 57 54 [2] 4c 52 [2] 50 55 [2] 4c 7a }

  condition:
    any of them
}