rule TTP_XOR_QUAD_CurrentVersionRun_0a1e {
  strings:
    $key_0a1e = { 59 71 [2] 7d 7f [2] 56 53 [2] 78 71 [2] 6c 6a [2] 63 70 [2] 7d 6d [2] 7f 6c [2] 64 6a [2] 78 6d [2] 64 42 }

  condition:
    any of them
}