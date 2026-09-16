rule TTP_XOR_QUAD_CurrentVersionRun_3034 {
  strings:
    $key_3034 = { 63 5b [2] 47 55 [2] 6c 79 [2] 42 5b [2] 56 40 [2] 59 5a [2] 47 47 [2] 45 46 [2] 5e 40 [2] 42 47 [2] 5e 68 }

  condition:
    any of them
}