rule TTP_XOR_QUAD_CurrentVersionRun_3513 {
  strings:
    $key_3513 = { 66 7c [2] 42 72 [2] 69 5e [2] 47 7c [2] 53 67 [2] 5c 7d [2] 42 60 [2] 40 61 [2] 5b 67 [2] 47 60 [2] 5b 4f }

  condition:
    any of them
}