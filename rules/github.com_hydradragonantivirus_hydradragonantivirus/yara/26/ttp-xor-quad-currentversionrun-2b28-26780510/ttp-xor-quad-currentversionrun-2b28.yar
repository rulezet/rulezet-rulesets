rule TTP_XOR_QUAD_CurrentVersionRun_2b28 {
  strings:
    $key_2b28 = { 78 47 [2] 5c 49 [2] 77 65 [2] 59 47 [2] 4d 5c [2] 42 46 [2] 5c 5b [2] 5e 5a [2] 45 5c [2] 59 5b [2] 45 74 }

  condition:
    any of them
}