rule TTP_XOR_QUAD_CurrentVersionRun_0d31 {
  strings:
    $key_0d31 = { 5e 5e [2] 7a 50 [2] 51 7c [2] 7f 5e [2] 6b 45 [2] 64 5f [2] 7a 42 [2] 78 43 [2] 63 45 [2] 7f 42 [2] 63 6d }

  condition:
    any of them
}