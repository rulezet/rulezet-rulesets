rule TTP_XOR_QUAD_CurrentVersionRun_3a00 {
  strings:
    $key_3a00 = { 69 6f [2] 4d 61 [2] 66 4d [2] 48 6f [2] 5c 74 [2] 53 6e [2] 4d 73 [2] 4f 72 [2] 54 74 [2] 48 73 [2] 54 5c }

  condition:
    any of them
}