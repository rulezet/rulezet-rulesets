rule TTP_XOR_QUAD_CurrentVersionRun_1631 {
  strings:
    $key_1631 = { 45 5e [2] 61 50 [2] 4a 7c [2] 64 5e [2] 70 45 [2] 7f 5f [2] 61 42 [2] 63 43 [2] 78 45 [2] 64 42 [2] 78 6d }

  condition:
    any of them
}