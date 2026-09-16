rule TTP_XOR_QUAD_CurrentVersionRun_3211 {
  strings:
    $key_3211 = { 61 7e [2] 45 70 [2] 6e 5c [2] 40 7e [2] 54 65 [2] 5b 7f [2] 45 62 [2] 47 63 [2] 5c 65 [2] 40 62 [2] 5c 4d }

  condition:
    any of them
}