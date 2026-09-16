rule TTP_XOR_QUAD_CurrentVersionRun_1662 {
  strings:
    $key_1662 = { 45 0d [2] 61 03 [2] 4a 2f [2] 64 0d [2] 70 16 [2] 7f 0c [2] 61 11 [2] 63 10 [2] 78 16 [2] 64 11 [2] 78 3e }

  condition:
    any of them
}