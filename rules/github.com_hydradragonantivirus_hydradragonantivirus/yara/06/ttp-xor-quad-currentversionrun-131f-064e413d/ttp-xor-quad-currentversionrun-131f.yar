rule TTP_XOR_QUAD_CurrentVersionRun_131f {
  strings:
    $key_131f = { 40 70 [2] 64 7e [2] 4f 52 [2] 61 70 [2] 75 6b [2] 7a 71 [2] 64 6c [2] 66 6d [2] 7d 6b [2] 61 6c [2] 7d 43 }

  condition:
    any of them
}