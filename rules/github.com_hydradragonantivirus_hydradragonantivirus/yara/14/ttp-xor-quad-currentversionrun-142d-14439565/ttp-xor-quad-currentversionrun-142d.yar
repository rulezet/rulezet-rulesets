rule TTP_XOR_QUAD_CurrentVersionRun_142d {
  strings:
    $key_142d = { 47 42 [2] 63 4c [2] 48 60 [2] 66 42 [2] 72 59 [2] 7d 43 [2] 63 5e [2] 61 5f [2] 7a 59 [2] 66 5e [2] 7a 71 }

  condition:
    any of them
}