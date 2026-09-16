rule TTP_XOR_QUAD_CurrentVersionRun_3962 {
  strings:
    $key_3962 = { 6a 0d [2] 4e 03 [2] 65 2f [2] 4b 0d [2] 5f 16 [2] 50 0c [2] 4e 11 [2] 4c 10 [2] 57 16 [2] 4b 11 [2] 57 3e }

  condition:
    any of them
}