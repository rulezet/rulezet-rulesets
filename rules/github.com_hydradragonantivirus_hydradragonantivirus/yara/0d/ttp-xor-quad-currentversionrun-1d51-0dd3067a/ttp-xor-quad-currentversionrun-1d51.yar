rule TTP_XOR_QUAD_CurrentVersionRun_1d51 {
  strings:
    $key_1d51 = { 4e 3e [2] 6a 30 [2] 41 1c [2] 6f 3e [2] 7b 25 [2] 74 3f [2] 6a 22 [2] 68 23 [2] 73 25 [2] 6f 22 [2] 73 0d }

  condition:
    any of them
}