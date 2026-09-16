rule TTP_XOR_QUAD_CurrentVersionRun_1226 {
  strings:
    $key_1226 = { 41 49 [2] 65 47 [2] 4e 6b [2] 60 49 [2] 74 52 [2] 7b 48 [2] 65 55 [2] 67 54 [2] 7c 52 [2] 60 55 [2] 7c 7a }

  condition:
    any of them
}