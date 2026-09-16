rule TTP_XOR_QUAD_CurrentVersionRun_1902 {
  strings:
    $key_1902 = { 4a 6d [2] 6e 63 [2] 45 4f [2] 6b 6d [2] 7f 76 [2] 70 6c [2] 6e 71 [2] 6c 70 [2] 77 76 [2] 6b 71 [2] 77 5e }

  condition:
    any of them
}