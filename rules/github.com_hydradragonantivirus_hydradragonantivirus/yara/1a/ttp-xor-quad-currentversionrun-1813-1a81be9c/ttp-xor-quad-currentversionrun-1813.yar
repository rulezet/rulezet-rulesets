rule TTP_XOR_QUAD_CurrentVersionRun_1813 {
  strings:
    $key_1813 = { 4b 7c [2] 6f 72 [2] 44 5e [2] 6a 7c [2] 7e 67 [2] 71 7d [2] 6f 60 [2] 6d 61 [2] 76 67 [2] 6a 60 [2] 76 4f }

  condition:
    any of them
}