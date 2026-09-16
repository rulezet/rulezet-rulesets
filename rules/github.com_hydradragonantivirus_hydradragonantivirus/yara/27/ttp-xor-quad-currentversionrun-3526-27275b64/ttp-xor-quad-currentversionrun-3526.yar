rule TTP_XOR_QUAD_CurrentVersionRun_3526 {
  strings:
    $key_3526 = { 66 49 [2] 42 47 [2] 69 6b [2] 47 49 [2] 53 52 [2] 5c 48 [2] 42 55 [2] 40 54 [2] 5b 52 [2] 47 55 [2] 5b 7a }

  condition:
    any of them
}