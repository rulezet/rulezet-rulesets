rule TTP_XOR_QUAD_CurrentVersionRun_2eff {
  strings:
    $key_2eff = { 7d 90 [2] 59 9e [2] 72 b2 [2] 5c 90 [2] 48 8b [2] 47 91 [2] 59 8c [2] 5b 8d [2] 40 8b [2] 5c 8c [2] 40 a3 }

  condition:
    any of them
}