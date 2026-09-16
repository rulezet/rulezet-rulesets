rule TTP_XOR_QUAD_CurrentVersionRun_7d02 {
  strings:
    $key_7d02 = { 2e 6d [2] 0a 63 [2] 21 4f [2] 0f 6d [2] 1b 76 [2] 14 6c [2] 0a 71 [2] 08 70 [2] 13 76 [2] 0f 71 [2] 13 5e }

  condition:
    any of them
}