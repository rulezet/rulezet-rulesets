rule TTP_XOR_QUAD_CurrentVersionRun_1220 {
  strings:
    $key_1220 = { 41 4f [2] 65 41 [2] 4e 6d [2] 60 4f [2] 74 54 [2] 7b 4e [2] 65 53 [2] 67 52 [2] 7c 54 [2] 60 53 [2] 7c 7c }

  condition:
    any of them
}