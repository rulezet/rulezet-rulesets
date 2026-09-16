rule TTP_XOR_QUAD_CurrentVersionRun_070e {
  strings:
    $key_070e = { 54 61 [2] 70 6f [2] 5b 43 [2] 75 61 [2] 61 7a [2] 6e 60 [2] 70 7d [2] 72 7c [2] 69 7a [2] 75 7d [2] 69 52 }

  condition:
    any of them
}