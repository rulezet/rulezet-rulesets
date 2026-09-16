rule TTP_XOR_QUAD_CurrentVersionRun_0262 {
  strings:
    $key_0262 = { 51 0d [2] 75 03 [2] 5e 2f [2] 70 0d [2] 64 16 [2] 6b 0c [2] 75 11 [2] 77 10 [2] 6c 16 [2] 70 11 [2] 6c 3e }

  condition:
    any of them
}