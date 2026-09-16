rule TTP_XOR_QUAD_CurrentVersionRun_f126 {
  strings:
    $key_f126 = { a2 49 [2] 86 47 [2] ad 6b [2] 83 49 [2] 97 52 [2] 98 48 [2] 86 55 [2] 84 54 [2] 9f 52 [2] 83 55 [2] 9f 7a }

  condition:
    any of them
}