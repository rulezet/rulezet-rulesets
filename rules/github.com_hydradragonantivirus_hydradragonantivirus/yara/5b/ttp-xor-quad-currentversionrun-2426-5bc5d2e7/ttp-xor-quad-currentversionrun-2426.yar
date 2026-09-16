rule TTP_XOR_QUAD_CurrentVersionRun_2426 {
  strings:
    $key_2426 = { 77 49 [2] 53 47 [2] 78 6b [2] 56 49 [2] 42 52 [2] 4d 48 [2] 53 55 [2] 51 54 [2] 4a 52 [2] 56 55 [2] 4a 7a }

  condition:
    any of them
}