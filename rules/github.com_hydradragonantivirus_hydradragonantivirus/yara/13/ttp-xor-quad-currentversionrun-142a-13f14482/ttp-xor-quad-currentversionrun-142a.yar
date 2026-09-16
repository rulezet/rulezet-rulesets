rule TTP_XOR_QUAD_CurrentVersionRun_142a {
  strings:
    $key_142a = { 47 45 [2] 63 4b [2] 48 67 [2] 66 45 [2] 72 5e [2] 7d 44 [2] 63 59 [2] 61 58 [2] 7a 5e [2] 66 59 [2] 7a 76 }

  condition:
    any of them
}