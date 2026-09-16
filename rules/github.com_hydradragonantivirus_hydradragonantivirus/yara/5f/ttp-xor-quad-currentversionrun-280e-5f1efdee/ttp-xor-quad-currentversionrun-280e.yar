rule TTP_XOR_QUAD_CurrentVersionRun_280e {
  strings:
    $key_280e = { 7b 61 [2] 5f 6f [2] 74 43 [2] 5a 61 [2] 4e 7a [2] 41 60 [2] 5f 7d [2] 5d 7c [2] 46 7a [2] 5a 7d [2] 46 52 }

  condition:
    any of them
}