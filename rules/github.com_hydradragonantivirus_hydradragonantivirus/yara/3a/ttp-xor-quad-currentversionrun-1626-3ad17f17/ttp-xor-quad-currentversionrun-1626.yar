rule TTP_XOR_QUAD_CurrentVersionRun_1626 {
  strings:
    $key_1626 = { 45 49 [2] 61 47 [2] 4a 6b [2] 64 49 [2] 70 52 [2] 7f 48 [2] 61 55 [2] 63 54 [2] 78 52 [2] 64 55 [2] 78 7a }

  condition:
    any of them
}