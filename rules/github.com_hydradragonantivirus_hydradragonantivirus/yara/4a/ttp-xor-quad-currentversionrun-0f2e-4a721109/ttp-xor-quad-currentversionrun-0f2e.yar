rule TTP_XOR_QUAD_CurrentVersionRun_0f2e {
  strings:
    $key_0f2e = { 5c 41 [2] 78 4f [2] 53 63 [2] 7d 41 [2] 69 5a [2] 66 40 [2] 78 5d [2] 7a 5c [2] 61 5a [2] 7d 5d [2] 61 72 }

  condition:
    any of them
}