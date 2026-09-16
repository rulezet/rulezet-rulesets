rule TTP_XOR_QUAD_CurrentVersionRun_190e {
  strings:
    $key_190e = { 4a 61 [2] 6e 6f [2] 45 43 [2] 6b 61 [2] 7f 7a [2] 70 60 [2] 6e 7d [2] 6c 7c [2] 77 7a [2] 6b 7d [2] 77 52 }

  condition:
    any of them
}