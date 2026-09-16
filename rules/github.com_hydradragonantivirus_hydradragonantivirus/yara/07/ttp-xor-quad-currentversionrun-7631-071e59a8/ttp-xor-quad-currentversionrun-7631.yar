rule TTP_XOR_QUAD_CurrentVersionRun_7631 {
  strings:
    $key_7631 = { 25 5e [2] 01 50 [2] 2a 7c [2] 04 5e [2] 10 45 [2] 1f 5f [2] 01 42 [2] 03 43 [2] 18 45 [2] 04 42 [2] 18 6d }

  condition:
    any of them
}