rule TTP_XOR_QUAD_CurrentVersionRun_7a1f {
  strings:
    $key_7a1f = { 29 70 [2] 0d 7e [2] 26 52 [2] 08 70 [2] 1c 6b [2] 13 71 [2] 0d 6c [2] 0f 6d [2] 14 6b [2] 08 6c [2] 14 43 }

  condition:
    any of them
}