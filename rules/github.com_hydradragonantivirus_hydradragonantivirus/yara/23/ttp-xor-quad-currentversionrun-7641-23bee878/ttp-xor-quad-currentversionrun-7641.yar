rule TTP_XOR_QUAD_CurrentVersionRun_7641 {
  strings:
    $key_7641 = { 25 2e [2] 01 20 [2] 2a 0c [2] 04 2e [2] 10 35 [2] 1f 2f [2] 01 32 [2] 03 33 [2] 18 35 [2] 04 32 [2] 18 1d }

  condition:
    any of them
}