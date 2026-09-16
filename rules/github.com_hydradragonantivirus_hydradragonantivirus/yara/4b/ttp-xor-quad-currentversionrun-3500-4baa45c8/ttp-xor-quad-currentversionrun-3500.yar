rule TTP_XOR_QUAD_CurrentVersionRun_3500 {
  strings:
    $key_3500 = { 66 6f [2] 42 61 [2] 69 4d [2] 47 6f [2] 53 74 [2] 5c 6e [2] 42 73 [2] 40 72 [2] 5b 74 [2] 47 73 [2] 5b 5c }

  condition:
    any of them
}