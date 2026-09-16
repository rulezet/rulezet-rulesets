rule TTP_XOR_QUAD_CurrentVersionRun_2620 {
  strings:
    $key_2620 = { 75 4f [2] 51 41 [2] 7a 6d [2] 54 4f [2] 40 54 [2] 4f 4e [2] 51 53 [2] 53 52 [2] 48 54 [2] 54 53 [2] 48 7c }

  condition:
    any of them
}