rule TTP_XOR_QUAD_CurrentVersionRun_7841 {
  strings:
    $key_7841 = { 2b 2e [2] 0f 20 [2] 24 0c [2] 0a 2e [2] 1e 35 [2] 11 2f [2] 0f 32 [2] 0d 33 [2] 16 35 [2] 0a 32 [2] 16 1d }

  condition:
    any of them
}