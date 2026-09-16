rule TTP_XOR_QUAD_CurrentVersionRun_0e62 {
  strings:
    $key_0e62 = { 5d 0d [2] 79 03 [2] 52 2f [2] 7c 0d [2] 68 16 [2] 67 0c [2] 79 11 [2] 7b 10 [2] 60 16 [2] 7c 11 [2] 60 3e }

  condition:
    any of them
}