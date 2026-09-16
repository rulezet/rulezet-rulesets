rule TTP_XOR_QUAD_CurrentVersionRun_6250 {
  strings:
    $key_6250 = { 31 3f [2] 15 31 [2] 3e 1d [2] 10 3f [2] 04 24 [2] 0b 3e [2] 15 23 [2] 17 22 [2] 0c 24 [2] 10 23 [2] 0c 0c }

  condition:
    any of them
}