rule TTP_XOR_QUAD_CurrentVersionRun_0f1f {
  strings:
    $key_0f1f = { 5c 70 [2] 78 7e [2] 53 52 [2] 7d 70 [2] 69 6b [2] 66 71 [2] 78 6c [2] 7a 6d [2] 61 6b [2] 7d 6c [2] 61 43 }

  condition:
    any of them
}