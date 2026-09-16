rule TTP_XOR_QUAD_CurrentVersionRun_3044 {
  strings:
    $key_3044 = { 63 2b [2] 47 25 [2] 6c 09 [2] 42 2b [2] 56 30 [2] 59 2a [2] 47 37 [2] 45 36 [2] 5e 30 [2] 42 37 [2] 5e 18 }

  condition:
    any of them
}