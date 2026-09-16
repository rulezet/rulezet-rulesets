rule TTP_XOR_QUAD_CurrentVersionRun_2e19 {
  strings:
    $key_2e19 = { 7d 76 [2] 59 78 [2] 72 54 [2] 5c 76 [2] 48 6d [2] 47 77 [2] 59 6a [2] 5b 6b [2] 40 6d [2] 5c 6a [2] 40 45 }

  condition:
    any of them
}