rule TTP_XOR_QUAD_CurrentVersionRun_c5e7 {
  strings:
    $key_c5e7 = { 96 88 [2] b2 86 [2] 99 aa [2] b7 88 [2] a3 93 [2] ac 89 [2] b2 94 [2] b0 95 [2] ab 93 [2] b7 94 [2] ab bb }

  condition:
    any of them
}