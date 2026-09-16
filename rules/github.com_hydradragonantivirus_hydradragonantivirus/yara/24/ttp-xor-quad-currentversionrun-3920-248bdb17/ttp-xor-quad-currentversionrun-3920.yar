rule TTP_XOR_QUAD_CurrentVersionRun_3920 {
  strings:
    $key_3920 = { 6a 4f [2] 4e 41 [2] 65 6d [2] 4b 4f [2] 5f 54 [2] 50 4e [2] 4e 53 [2] 4c 52 [2] 57 54 [2] 4b 53 [2] 57 7c }

  condition:
    any of them
}