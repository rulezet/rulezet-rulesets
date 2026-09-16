rule TTP_XOR_QUAD_CurrentVersionRun_0220 {
  strings:
    $key_0220 = { 51 4f [2] 75 41 [2] 5e 6d [2] 70 4f [2] 64 54 [2] 6b 4e [2] 75 53 [2] 77 52 [2] 6c 54 [2] 70 53 [2] 6c 7c }

  condition:
    any of them
}