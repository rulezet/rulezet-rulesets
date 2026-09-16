rule TTP_XOR_QUAD_CurrentVersionRun_5741 {
  strings:
    $key_5741 = { 04 2e [2] 20 20 [2] 0b 0c [2] 25 2e [2] 31 35 [2] 3e 2f [2] 20 32 [2] 22 33 [2] 39 35 [2] 25 32 [2] 39 1d }

  condition:
    any of them
}