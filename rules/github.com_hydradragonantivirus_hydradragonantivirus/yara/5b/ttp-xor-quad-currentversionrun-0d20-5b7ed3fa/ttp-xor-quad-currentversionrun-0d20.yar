rule TTP_XOR_QUAD_CurrentVersionRun_0d20 {
  strings:
    $key_0d20 = { 5e 4f [2] 7a 41 [2] 51 6d [2] 7f 4f [2] 6b 54 [2] 64 4e [2] 7a 53 [2] 78 52 [2] 63 54 [2] 7f 53 [2] 63 7c }

  condition:
    any of them
}