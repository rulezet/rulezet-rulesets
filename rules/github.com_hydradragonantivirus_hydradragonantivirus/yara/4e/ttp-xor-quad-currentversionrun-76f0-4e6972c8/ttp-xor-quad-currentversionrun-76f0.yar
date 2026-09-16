rule TTP_XOR_QUAD_CurrentVersionRun_76f0 {
  strings:
    $key_76f0 = { 25 9f [2] 01 91 [2] 2a bd [2] 04 9f [2] 10 84 [2] 1f 9e [2] 01 83 [2] 03 82 [2] 18 84 [2] 04 83 [2] 18 ac }

  condition:
    any of them
}