rule TTP_XOR_QUAD_CurrentVersionRun_3b2e {
  strings:
    $key_3b2e = { 68 41 [2] 4c 4f [2] 67 63 [2] 49 41 [2] 5d 5a [2] 52 40 [2] 4c 5d [2] 4e 5c [2] 55 5a [2] 49 5d [2] 55 72 }

  condition:
    any of them
}