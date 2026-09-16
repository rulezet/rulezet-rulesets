rule TTP_XOR_QUAD_CurrentVersionRun_0920 {
  strings:
    $key_0920 = { 5a 4f [2] 7e 41 [2] 55 6d [2] 7b 4f [2] 6f 54 [2] 60 4e [2] 7e 53 [2] 7c 52 [2] 67 54 [2] 7b 53 [2] 67 7c }

  condition:
    any of them
}