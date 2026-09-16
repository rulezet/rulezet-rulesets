rule TTP_XOR_QUAD_CurrentVersionRun_286a {
  strings:
    $key_286a = { 7b 05 [2] 5f 0b [2] 74 27 [2] 5a 05 [2] 4e 1e [2] 41 04 [2] 5f 19 [2] 5d 18 [2] 46 1e [2] 5a 19 [2] 46 36 }

  condition:
    any of them
}