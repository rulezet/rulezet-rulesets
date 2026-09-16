rule TTP_XOR_QUAD_CurrentVersionRun_f641 {
  strings:
    $key_f641 = { a5 2e [2] 81 20 [2] aa 0c [2] 84 2e [2] 90 35 [2] 9f 2f [2] 81 32 [2] 83 33 [2] 98 35 [2] 84 32 [2] 98 1d }

  condition:
    any of them
}