rule TTP_XOR_QUAD_CurrentVersionRun_163a {
  strings:
    $key_163a = { 45 55 [2] 61 5b [2] 4a 77 [2] 64 55 [2] 70 4e [2] 7f 54 [2] 61 49 [2] 63 48 [2] 78 4e [2] 64 49 [2] 78 66 }

  condition:
    any of them
}