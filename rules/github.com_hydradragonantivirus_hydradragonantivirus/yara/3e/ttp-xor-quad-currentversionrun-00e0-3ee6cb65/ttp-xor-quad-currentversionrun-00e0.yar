rule TTP_XOR_QUAD_CurrentVersionRun_00e0 {
  strings:
    $key_00e0 = { 53 8f [2] 77 81 [2] 5c ad [2] 72 8f [2] 66 94 [2] 69 8e [2] 77 93 [2] 75 92 [2] 6e 94 [2] 72 93 [2] 6e bc }

  condition:
    any of them
}