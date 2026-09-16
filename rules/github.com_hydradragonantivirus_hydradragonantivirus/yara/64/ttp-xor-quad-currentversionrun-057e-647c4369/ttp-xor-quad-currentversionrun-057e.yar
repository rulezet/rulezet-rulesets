rule TTP_XOR_QUAD_CurrentVersionRun_057e {
  strings:
    $key_057e = { 56 11 [2] 72 1f [2] 59 33 [2] 77 11 [2] 63 0a [2] 6c 10 [2] 72 0d [2] 70 0c [2] 6b 0a [2] 77 0d [2] 6b 22 }

  condition:
    any of them
}