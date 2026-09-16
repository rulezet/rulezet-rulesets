rule TTP_XOR_QUAD_CurrentVersionRun_2601 {
  strings:
    $key_2601 = { 75 6e [2] 51 60 [2] 7a 4c [2] 54 6e [2] 40 75 [2] 4f 6f [2] 51 72 [2] 53 73 [2] 48 75 [2] 54 72 [2] 48 5d }

  condition:
    any of them
}