rule TTP_XOR_QUAD_CurrentVersionRun_1a2e {
  strings:
    $key_1a2e = { 49 41 [2] 6d 4f [2] 46 63 [2] 68 41 [2] 7c 5a [2] 73 40 [2] 6d 5d [2] 6f 5c [2] 74 5a [2] 68 5d [2] 74 72 }

  condition:
    any of them
}