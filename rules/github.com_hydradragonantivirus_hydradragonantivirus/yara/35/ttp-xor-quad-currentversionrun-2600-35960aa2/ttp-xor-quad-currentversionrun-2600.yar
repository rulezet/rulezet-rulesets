rule TTP_XOR_QUAD_CurrentVersionRun_2600 {
  strings:
    $key_2600 = { 75 6f [2] 51 61 [2] 7a 4d [2] 54 6f [2] 40 74 [2] 4f 6e [2] 51 73 [2] 53 72 [2] 48 74 [2] 54 73 [2] 48 5c }

  condition:
    any of them
}