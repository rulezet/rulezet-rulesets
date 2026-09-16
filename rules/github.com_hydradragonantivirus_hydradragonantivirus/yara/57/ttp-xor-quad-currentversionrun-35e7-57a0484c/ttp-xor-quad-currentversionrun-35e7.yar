rule TTP_XOR_QUAD_CurrentVersionRun_35e7 {
  strings:
    $key_35e7 = { 66 88 [2] 42 86 [2] 69 aa [2] 47 88 [2] 53 93 [2] 5c 89 [2] 42 94 [2] 40 95 [2] 5b 93 [2] 47 94 [2] 5b bb }

  condition:
    any of them
}