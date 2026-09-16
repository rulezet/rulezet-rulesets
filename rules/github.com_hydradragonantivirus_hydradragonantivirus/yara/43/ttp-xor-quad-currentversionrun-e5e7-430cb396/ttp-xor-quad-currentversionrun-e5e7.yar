rule TTP_XOR_QUAD_CurrentVersionRun_e5e7 {
  strings:
    $key_e5e7 = { b6 88 [2] 92 86 [2] b9 aa [2] 97 88 [2] 83 93 [2] 8c 89 [2] 92 94 [2] 90 95 [2] 8b 93 [2] 97 94 [2] 8b bb }

  condition:
    any of them
}