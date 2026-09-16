rule TTP_XOR_QUAD_CurrentVersionRun_3262 {
  strings:
    $key_3262 = { 61 0d [2] 45 03 [2] 6e 2f [2] 40 0d [2] 54 16 [2] 5b 0c [2] 45 11 [2] 47 10 [2] 5c 16 [2] 40 11 [2] 5c 3e }

  condition:
    any of them
}