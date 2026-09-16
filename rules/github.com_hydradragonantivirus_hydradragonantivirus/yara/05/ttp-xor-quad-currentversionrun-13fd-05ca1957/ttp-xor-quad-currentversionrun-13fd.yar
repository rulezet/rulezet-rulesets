rule TTP_XOR_QUAD_CurrentVersionRun_13fd {
  strings:
    $key_13fd = { 40 92 [2] 64 9c [2] 4f b0 [2] 61 92 [2] 75 89 [2] 7a 93 [2] 64 8e [2] 66 8f [2] 7d 89 [2] 61 8e [2] 7d a1 }

  condition:
    any of them
}