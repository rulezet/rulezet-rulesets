rule TTP_XOR_QUAD_CurrentVersionRun_e6e7 {
  strings:
    $key_e6e7 = { b5 88 [2] 91 86 [2] ba aa [2] 94 88 [2] 80 93 [2] 8f 89 [2] 91 94 [2] 93 95 [2] 88 93 [2] 94 94 [2] 88 bb }

  condition:
    any of them
}