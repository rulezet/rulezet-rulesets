rule TTP_XOR_QUAD_CurrentVersionRun_0a23 {
  strings:
    $key_0a23 = { 59 4c [2] 7d 42 [2] 56 6e [2] 78 4c [2] 6c 57 [2] 63 4d [2] 7d 50 [2] 7f 51 [2] 64 57 [2] 78 50 [2] 64 7f }

  condition:
    any of them
}