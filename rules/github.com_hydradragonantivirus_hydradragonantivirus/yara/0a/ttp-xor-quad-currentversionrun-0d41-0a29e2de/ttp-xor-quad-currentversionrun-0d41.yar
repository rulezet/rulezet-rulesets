rule TTP_XOR_QUAD_CurrentVersionRun_0d41 {
  strings:
    $key_0d41 = { 5e 2e [2] 7a 20 [2] 51 0c [2] 7f 2e [2] 6b 35 [2] 64 2f [2] 7a 32 [2] 78 33 [2] 63 35 [2] 7f 32 [2] 63 1d }

  condition:
    any of them
}