rule TTP_XOR_QUAD_CurrentVersionRun_e701 {
  strings:
    $key_e701 = { b4 6e [2] 90 60 [2] bb 4c [2] 95 6e [2] 81 75 [2] 8e 6f [2] 90 72 [2] 92 73 [2] 89 75 [2] 95 72 [2] 89 5d }

  condition:
    any of them
}