rule TTP_XOR_QUAD_CurrentVersionRun_6251 {
  strings:
    $key_6251 = { 31 3e [2] 15 30 [2] 3e 1c [2] 10 3e [2] 04 25 [2] 0b 3f [2] 15 22 [2] 17 23 [2] 0c 25 [2] 10 22 [2] 0c 0d }

  condition:
    any of them
}