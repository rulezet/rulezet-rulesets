rule TTP_XOR_QUAD_CurrentVersionRun_fefd {
  strings:
    $key_fefd = { ad 92 [2] 89 9c [2] a2 b0 [2] 8c 92 [2] 98 89 [2] 97 93 [2] 89 8e [2] 8b 8f [2] 90 89 [2] 8c 8e [2] 90 a1 }

  condition:
    any of them
}