rule TTP_XOR_QUAD_CurrentVersionRun_2111 {
  strings:
    $key_2111 = { 72 7e [2] 56 70 [2] 7d 5c [2] 53 7e [2] 47 65 [2] 48 7f [2] 56 62 [2] 54 63 [2] 4f 65 [2] 53 62 [2] 4f 4d }

  condition:
    any of them
}