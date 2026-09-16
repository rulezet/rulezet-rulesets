rule TTP_XOR_QUAD_CurrentVersionRun_780e {
  strings:
    $key_780e = { 2b 61 [2] 0f 6f [2] 24 43 [2] 0a 61 [2] 1e 7a [2] 11 60 [2] 0f 7d [2] 0d 7c [2] 16 7a [2] 0a 7d [2] 16 52 }

  condition:
    any of them
}