rule TTP_XOR_QUAD_CurrentVersionRun_0962 {
  strings:
    $key_0962 = { 5a 0d [2] 7e 03 [2] 55 2f [2] 7b 0d [2] 6f 16 [2] 60 0c [2] 7e 11 [2] 7c 10 [2] 67 16 [2] 7b 11 [2] 67 3e }

  condition:
    any of them
}