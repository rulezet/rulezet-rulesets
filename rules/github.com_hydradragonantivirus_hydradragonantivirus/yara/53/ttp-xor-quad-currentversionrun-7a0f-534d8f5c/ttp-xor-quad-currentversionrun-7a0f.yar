rule TTP_XOR_QUAD_CurrentVersionRun_7a0f {
  strings:
    $key_7a0f = { 29 60 [2] 0d 6e [2] 26 42 [2] 08 60 [2] 1c 7b [2] 13 61 [2] 0d 7c [2] 0f 7d [2] 14 7b [2] 08 7c [2] 14 53 }

  condition:
    any of them
}