rule TTP_XOR_QUAD_CurrentVersionRun_f97f {
  strings:
    $key_f97f = { aa 10 [2] 8e 1e [2] a5 32 [2] 8b 10 [2] 9f 0b [2] 90 11 [2] 8e 0c [2] 8c 0d [2] 97 0b [2] 8b 0c [2] 97 23 }

  condition:
    any of them
}