rule TTP_XOR_QUAD_CurrentVersionRun_130e {
  strings:
    $key_130e = { 40 61 [2] 64 6f [2] 4f 43 [2] 61 61 [2] 75 7a [2] 7a 60 [2] 64 7d [2] 66 7c [2] 7d 7a [2] 61 7d [2] 7d 52 }

  condition:
    any of them
}