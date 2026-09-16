rule TTP_XOR_QUAD_CurrentVersionRun_2202 {
  strings:
    $key_2202 = { 71 6d [2] 55 63 [2] 7e 4f [2] 50 6d [2] 44 76 [2] 4b 6c [2] 55 71 [2] 57 70 [2] 4c 76 [2] 50 71 [2] 4c 5e }

  condition:
    any of them
}