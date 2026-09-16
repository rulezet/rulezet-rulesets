rule TTP_XOR_QUAD_CurrentVersionRun_0d0e {
  strings:
    $key_0d0e = { 5e 61 [2] 7a 6f [2] 51 43 [2] 7f 61 [2] 6b 7a [2] 64 60 [2] 7a 7d [2] 78 7c [2] 63 7a [2] 7f 7d [2] 63 52 }

  condition:
    any of them
}