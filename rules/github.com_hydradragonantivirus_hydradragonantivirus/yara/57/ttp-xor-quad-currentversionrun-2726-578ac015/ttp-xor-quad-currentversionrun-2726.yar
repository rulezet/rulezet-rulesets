rule TTP_XOR_QUAD_CurrentVersionRun_2726 {
  strings:
    $key_2726 = { 74 49 [2] 50 47 [2] 7b 6b [2] 55 49 [2] 41 52 [2] 4e 48 [2] 50 55 [2] 52 54 [2] 49 52 [2] 55 55 [2] 49 7a }

  condition:
    any of them
}