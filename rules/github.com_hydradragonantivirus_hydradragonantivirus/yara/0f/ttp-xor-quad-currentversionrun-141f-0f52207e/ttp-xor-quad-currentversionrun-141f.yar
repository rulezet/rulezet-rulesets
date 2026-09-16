rule TTP_XOR_QUAD_CurrentVersionRun_141f {
  strings:
    $key_141f = { 47 70 [2] 63 7e [2] 48 52 [2] 66 70 [2] 72 6b [2] 7d 71 [2] 63 6c [2] 61 6d [2] 7a 6b [2] 66 6c [2] 7a 43 }

  condition:
    any of them
}