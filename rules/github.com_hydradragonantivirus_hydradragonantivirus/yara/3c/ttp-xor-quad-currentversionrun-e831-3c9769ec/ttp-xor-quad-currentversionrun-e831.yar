rule TTP_XOR_QUAD_CurrentVersionRun_e831 {
  strings:
    $key_e831 = { bb 5e [2] 9f 50 [2] b4 7c [2] 9a 5e [2] 8e 45 [2] 81 5f [2] 9f 42 [2] 9d 43 [2] 86 45 [2] 9a 42 [2] 86 6d }

  condition:
    any of them
}