rule TTP_XOR_QUAD_CurrentVersionRun_3a20 {
  strings:
    $key_3a20 = { 69 4f [2] 4d 41 [2] 66 6d [2] 48 4f [2] 5c 54 [2] 53 4e [2] 4d 53 [2] 4f 52 [2] 54 54 [2] 48 53 [2] 54 7c }

  condition:
    any of them
}