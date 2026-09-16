rule TTP_XOR_QUAD_CurrentVersionRun_e241 {
  strings:
    $key_e241 = { b1 2e [2] 95 20 [2] be 0c [2] 90 2e [2] 84 35 [2] 8b 2f [2] 95 32 [2] 97 33 [2] 8c 35 [2] 90 32 [2] 8c 1d }

  condition:
    any of them
}