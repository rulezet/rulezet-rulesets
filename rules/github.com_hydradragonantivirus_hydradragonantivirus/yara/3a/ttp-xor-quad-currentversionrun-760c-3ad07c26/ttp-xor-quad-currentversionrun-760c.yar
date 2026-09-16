rule TTP_XOR_QUAD_CurrentVersionRun_760c {
  strings:
    $key_760c = { 25 63 [2] 01 6d [2] 2a 41 [2] 04 63 [2] 10 78 [2] 1f 62 [2] 01 7f [2] 03 7e [2] 18 78 [2] 04 7f [2] 18 50 }

  condition:
    any of them
}