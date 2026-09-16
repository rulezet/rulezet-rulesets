rule TTP_XOR_QUAD_CurrentVersionRun_7821 {
  strings:
    $key_7821 = { 2b 4e [2] 0f 40 [2] 24 6c [2] 0a 4e [2] 1e 55 [2] 11 4f [2] 0f 52 [2] 0d 53 [2] 16 55 [2] 0a 52 [2] 16 7d }

  condition:
    any of them
}