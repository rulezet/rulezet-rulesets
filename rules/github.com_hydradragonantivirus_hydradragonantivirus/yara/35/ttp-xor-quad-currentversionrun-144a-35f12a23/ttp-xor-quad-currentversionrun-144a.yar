rule TTP_XOR_QUAD_CurrentVersionRun_144a {
  strings:
    $key_144a = { 47 25 [2] 63 2b [2] 48 07 [2] 66 25 [2] 72 3e [2] 7d 24 [2] 63 39 [2] 61 38 [2] 7a 3e [2] 66 39 [2] 7a 16 }

  condition:
    any of them
}