rule TTP_XOR_QUAD_CurrentVersionRun_7632 {
  strings:
    $key_7632 = { 25 5d [2] 01 53 [2] 2a 7f [2] 04 5d [2] 10 46 [2] 1f 5c [2] 01 41 [2] 03 40 [2] 18 46 [2] 04 41 [2] 18 6e }

  condition:
    any of them
}