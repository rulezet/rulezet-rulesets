rule TTP_XOR_QUAD_CurrentVersionRun_7620 {
  strings:
    $key_7620 = { 25 4f [2] 01 41 [2] 2a 6d [2] 04 4f [2] 10 54 [2] 1f 4e [2] 01 53 [2] 03 52 [2] 18 54 [2] 04 53 [2] 18 7c }

  condition:
    any of them
}