rule TTP_XOR_QUAD_CurrentVersionRun_1676 {
  strings:
    $key_1676 = { 45 19 [2] 61 17 [2] 4a 3b [2] 64 19 [2] 70 02 [2] 7f 18 [2] 61 05 [2] 63 04 [2] 78 02 [2] 64 05 [2] 78 2a }

  condition:
    any of them
}