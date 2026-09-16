rule TTP_XOR_QUAD_CurrentVersionRun_7634 {
  strings:
    $key_7634 = { 25 5b [2] 01 55 [2] 2a 79 [2] 04 5b [2] 10 40 [2] 1f 5a [2] 01 47 [2] 03 46 [2] 18 40 [2] 04 47 [2] 18 68 }

  condition:
    any of them
}