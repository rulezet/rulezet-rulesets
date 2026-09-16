rule TTP_XOR_QUAD_CurrentVersionRun_0513 {
  strings:
    $key_0513 = { 56 7c [2] 72 72 [2] 59 5e [2] 77 7c [2] 63 67 [2] 6c 7d [2] 72 60 [2] 70 61 [2] 6b 67 [2] 77 60 [2] 6b 4f }

  condition:
    any of them
}