rule TTP_XOR_QUAD_CurrentVersionRun_072e {
  strings:
    $key_072e = { 54 41 [2] 70 4f [2] 5b 63 [2] 75 41 [2] 61 5a [2] 6e 40 [2] 70 5d [2] 72 5c [2] 69 5a [2] 75 5d [2] 69 72 }

  condition:
    any of them
}