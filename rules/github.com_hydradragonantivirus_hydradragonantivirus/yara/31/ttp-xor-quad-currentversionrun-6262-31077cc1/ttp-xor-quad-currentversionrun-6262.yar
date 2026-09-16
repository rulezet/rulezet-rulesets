rule TTP_XOR_QUAD_CurrentVersionRun_6262 {
  strings:
    $key_6262 = { 31 0d [2] 15 03 [2] 3e 2f [2] 10 0d [2] 04 16 [2] 0b 0c [2] 15 11 [2] 17 10 [2] 0c 16 [2] 10 11 [2] 0c 3e }

  condition:
    any of them
}