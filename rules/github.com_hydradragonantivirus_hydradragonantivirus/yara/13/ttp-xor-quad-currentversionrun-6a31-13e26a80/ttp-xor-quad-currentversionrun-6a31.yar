rule TTP_XOR_QUAD_CurrentVersionRun_6a31 {
  strings:
    $key_6a31 = { 39 5e [2] 1d 50 [2] 36 7c [2] 18 5e [2] 0c 45 [2] 03 5f [2] 1d 42 [2] 1f 43 [2] 04 45 [2] 18 42 [2] 04 6d }

  condition:
    any of them
}