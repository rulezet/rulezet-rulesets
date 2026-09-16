rule TTP_XOR_QUAD_CurrentVersionRun_47f0 {
  strings:
    $key_47f0 = { 14 9f [2] 30 91 [2] 1b bd [2] 35 9f [2] 21 84 [2] 2e 9e [2] 30 83 [2] 32 82 [2] 29 84 [2] 35 83 [2] 29 ac }

  condition:
    any of them
}