rule TTP_XOR_QUAD_CurrentVersionRun_1912 {
  strings:
    $key_1912 = { 4a 7d [2] 6e 73 [2] 45 5f [2] 6b 7d [2] 7f 66 [2] 70 7c [2] 6e 61 [2] 6c 60 [2] 77 66 [2] 6b 61 [2] 77 4e }

  condition:
    any of them
}