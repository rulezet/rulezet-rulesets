rule TTP_XOR_QUAD_CurrentVersionRun_360e {
  strings:
    $key_360e = { 65 61 [2] 41 6f [2] 6a 43 [2] 44 61 [2] 50 7a [2] 5f 60 [2] 41 7d [2] 43 7c [2] 58 7a [2] 44 7d [2] 58 52 }

  condition:
    any of them
}