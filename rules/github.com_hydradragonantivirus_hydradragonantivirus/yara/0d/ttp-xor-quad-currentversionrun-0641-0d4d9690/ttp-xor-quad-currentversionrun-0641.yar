rule TTP_XOR_QUAD_CurrentVersionRun_0641 {
  strings:
    $key_0641 = { 55 2e [2] 71 20 [2] 5a 0c [2] 74 2e [2] 60 35 [2] 6f 2f [2] 71 32 [2] 73 33 [2] 68 35 [2] 74 32 [2] 68 1d }

  condition:
    any of them
}