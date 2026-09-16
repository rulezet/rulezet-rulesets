rule TTP_XOR_QUAD_CurrentVersionRun_2e00 {
  strings:
    $key_2e00 = { 7d 6f [2] 59 61 [2] 72 4d [2] 5c 6f [2] 48 74 [2] 47 6e [2] 59 73 [2] 5b 72 [2] 40 74 [2] 5c 73 [2] 40 5c }

  condition:
    any of them
}