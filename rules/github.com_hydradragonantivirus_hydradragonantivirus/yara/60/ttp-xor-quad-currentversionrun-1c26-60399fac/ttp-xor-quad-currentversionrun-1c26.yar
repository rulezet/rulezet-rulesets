rule TTP_XOR_QUAD_CurrentVersionRun_1c26 {
  strings:
    $key_1c26 = { 4f 49 [2] 6b 47 [2] 40 6b [2] 6e 49 [2] 7a 52 [2] 75 48 [2] 6b 55 [2] 69 54 [2] 72 52 [2] 6e 55 [2] 72 7a }

  condition:
    any of them
}