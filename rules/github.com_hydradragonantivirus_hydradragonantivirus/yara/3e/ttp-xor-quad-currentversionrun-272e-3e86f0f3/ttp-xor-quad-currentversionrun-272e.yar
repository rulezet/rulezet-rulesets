rule TTP_XOR_QUAD_CurrentVersionRun_272e {
  strings:
    $key_272e = { 74 41 [2] 50 4f [2] 7b 63 [2] 55 41 [2] 41 5a [2] 4e 40 [2] 50 5d [2] 52 5c [2] 49 5a [2] 55 5d [2] 49 72 }

  condition:
    any of them
}