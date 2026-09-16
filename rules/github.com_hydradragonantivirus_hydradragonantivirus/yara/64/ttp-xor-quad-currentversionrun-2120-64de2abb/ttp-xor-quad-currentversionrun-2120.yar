rule TTP_XOR_QUAD_CurrentVersionRun_2120 {
  strings:
    $key_2120 = { 72 4f [2] 56 41 [2] 7d 6d [2] 53 4f [2] 47 54 [2] 48 4e [2] 56 53 [2] 54 52 [2] 4f 54 [2] 53 53 [2] 4f 7c }

  condition:
    any of them
}