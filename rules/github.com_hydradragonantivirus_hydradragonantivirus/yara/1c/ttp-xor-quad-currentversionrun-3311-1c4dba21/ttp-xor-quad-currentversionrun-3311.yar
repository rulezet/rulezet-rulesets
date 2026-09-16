rule TTP_XOR_QUAD_CurrentVersionRun_3311 {
  strings:
    $key_3311 = { 60 7e [2] 44 70 [2] 6f 5c [2] 41 7e [2] 55 65 [2] 5a 7f [2] 44 62 [2] 46 63 [2] 5d 65 [2] 41 62 [2] 5d 4d }

  condition:
    any of them
}