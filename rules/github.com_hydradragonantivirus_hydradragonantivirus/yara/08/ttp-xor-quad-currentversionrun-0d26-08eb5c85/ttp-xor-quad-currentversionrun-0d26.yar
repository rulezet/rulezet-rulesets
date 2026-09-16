rule TTP_XOR_QUAD_CurrentVersionRun_0d26 {
  strings:
    $key_0d26 = { 5e 49 [2] 7a 47 [2] 51 6b [2] 7f 49 [2] 6b 52 [2] 64 48 [2] 7a 55 [2] 78 54 [2] 63 52 [2] 7f 55 [2] 63 7a }

  condition:
    any of them
}