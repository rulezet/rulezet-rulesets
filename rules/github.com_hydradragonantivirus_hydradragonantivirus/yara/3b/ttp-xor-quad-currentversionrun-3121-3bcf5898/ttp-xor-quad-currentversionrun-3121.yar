rule TTP_XOR_QUAD_CurrentVersionRun_3121 {
  strings:
    $key_3121 = { 62 4e [2] 46 40 [2] 6d 6c [2] 43 4e [2] 57 55 [2] 58 4f [2] 46 52 [2] 44 53 [2] 5f 55 [2] 43 52 [2] 5f 7d }

  condition:
    any of them
}