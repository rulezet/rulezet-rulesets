rule TTP_XOR_QUAD_CurrentVersionRun_3813 {
  strings:
    $key_3813 = { 6b 7c [2] 4f 72 [2] 64 5e [2] 4a 7c [2] 5e 67 [2] 51 7d [2] 4f 60 [2] 4d 61 [2] 56 67 [2] 4a 60 [2] 56 4f }

  condition:
    any of them
}