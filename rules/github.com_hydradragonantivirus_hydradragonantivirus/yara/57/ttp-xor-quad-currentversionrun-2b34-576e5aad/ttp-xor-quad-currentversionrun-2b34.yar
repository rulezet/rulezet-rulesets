rule TTP_XOR_QUAD_CurrentVersionRun_2b34 {
  strings:
    $key_2b34 = { 78 5b [2] 5c 55 [2] 77 79 [2] 59 5b [2] 4d 40 [2] 42 5a [2] 5c 47 [2] 5e 46 [2] 45 40 [2] 59 47 [2] 45 68 }

  condition:
    any of them
}