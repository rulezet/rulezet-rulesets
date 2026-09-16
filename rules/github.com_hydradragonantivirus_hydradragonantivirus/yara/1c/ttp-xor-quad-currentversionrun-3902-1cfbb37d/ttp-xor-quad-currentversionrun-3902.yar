rule TTP_XOR_QUAD_CurrentVersionRun_3902 {
  strings:
    $key_3902 = { 6a 6d [2] 4e 63 [2] 65 4f [2] 4b 6d [2] 5f 76 [2] 50 6c [2] 4e 71 [2] 4c 70 [2] 57 76 [2] 4b 71 [2] 57 5e }

  condition:
    any of them
}