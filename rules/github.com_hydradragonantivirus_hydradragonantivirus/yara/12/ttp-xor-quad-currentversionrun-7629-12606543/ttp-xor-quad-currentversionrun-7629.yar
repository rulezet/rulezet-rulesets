rule TTP_XOR_QUAD_CurrentVersionRun_7629 {
  strings:
    $key_7629 = { 25 46 [2] 01 48 [2] 2a 64 [2] 04 46 [2] 10 5d [2] 1f 47 [2] 01 5a [2] 03 5b [2] 18 5d [2] 04 5a [2] 18 75 }

  condition:
    any of them
}