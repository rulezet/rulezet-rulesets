rule TTP_XOR_QUAD_CurrentVersionRun_7d1f {
  strings:
    $key_7d1f = { 2e 70 [2] 0a 7e [2] 21 52 [2] 0f 70 [2] 1b 6b [2] 14 71 [2] 0a 6c [2] 08 6d [2] 13 6b [2] 0f 6c [2] 13 43 }

  condition:
    any of them
}