rule TTP_XOR_QUAD_CurrentVersionRun_1a31 {
  strings:
    $key_1a31 = { 49 5e [2] 6d 50 [2] 46 7c [2] 68 5e [2] 7c 45 [2] 73 5f [2] 6d 42 [2] 6f 43 [2] 74 45 [2] 68 42 [2] 74 6d }

  condition:
    any of them
}