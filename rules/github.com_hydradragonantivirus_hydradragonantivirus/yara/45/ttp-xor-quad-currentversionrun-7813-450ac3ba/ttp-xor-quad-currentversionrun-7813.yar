rule TTP_XOR_QUAD_CurrentVersionRun_7813 {
  strings:
    $key_7813 = { 2b 7c [2] 0f 72 [2] 24 5e [2] 0a 7c [2] 1e 67 [2] 11 7d [2] 0f 60 [2] 0d 61 [2] 16 67 [2] 0a 60 [2] 16 4f }

  condition:
    any of them
}