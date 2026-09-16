rule TTP_XOR_QUAD_CurrentVersionRun_eb41 {
  strings:
    $key_eb41 = { b8 2e [2] 9c 20 [2] b7 0c [2] 99 2e [2] 8d 35 [2] 82 2f [2] 9c 32 [2] 9e 33 [2] 85 35 [2] 99 32 [2] 85 1d }

  condition:
    any of them
}