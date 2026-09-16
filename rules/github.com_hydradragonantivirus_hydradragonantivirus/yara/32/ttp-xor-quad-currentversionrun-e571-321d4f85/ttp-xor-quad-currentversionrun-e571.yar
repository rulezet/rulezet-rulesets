rule TTP_XOR_QUAD_CurrentVersionRun_e571 {
  strings:
    $key_e571 = { b6 1e [2] 92 10 [2] b9 3c [2] 97 1e [2] 83 05 [2] 8c 1f [2] 92 02 [2] 90 03 [2] 8b 05 [2] 97 02 [2] 8b 2d }

  condition:
    any of them
}