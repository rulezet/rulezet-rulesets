rule TTP_XOR_QUAD_CurrentVersionRun_35eb {
  strings:
    $key_35eb = { 66 84 [2] 42 8a [2] 69 a6 [2] 47 84 [2] 53 9f [2] 5c 85 [2] 42 98 [2] 40 99 [2] 5b 9f [2] 47 98 [2] 5b b7 }

  condition:
    any of them
}