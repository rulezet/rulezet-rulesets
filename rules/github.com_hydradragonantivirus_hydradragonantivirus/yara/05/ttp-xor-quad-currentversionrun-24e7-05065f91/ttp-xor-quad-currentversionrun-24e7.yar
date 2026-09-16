rule TTP_XOR_QUAD_CurrentVersionRun_24e7 {
  strings:
    $key_24e7 = { 77 88 [2] 53 86 [2] 78 aa [2] 56 88 [2] 42 93 [2] 4d 89 [2] 53 94 [2] 51 95 [2] 4a 93 [2] 56 94 [2] 4a bb }

  condition:
    any of them
}