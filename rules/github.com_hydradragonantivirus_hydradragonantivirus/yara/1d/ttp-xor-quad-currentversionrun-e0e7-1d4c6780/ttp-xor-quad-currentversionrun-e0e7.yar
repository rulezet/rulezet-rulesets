rule TTP_XOR_QUAD_CurrentVersionRun_e0e7 {
  strings:
    $key_e0e7 = { b3 88 [2] 97 86 [2] bc aa [2] 92 88 [2] 86 93 [2] 89 89 [2] 97 94 [2] 95 95 [2] 8e 93 [2] 92 94 [2] 8e bb }

  condition:
    any of them
}