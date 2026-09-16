rule TTP_XOR_QUAD_CurrentVersionRun_0f1d {
  strings:
    $key_0f1d = { 5c 72 [2] 78 7c [2] 53 50 [2] 7d 72 [2] 69 69 [2] 66 73 [2] 78 6e [2] 7a 6f [2] 61 69 [2] 7d 6e [2] 61 41 }

  condition:
    any of them
}