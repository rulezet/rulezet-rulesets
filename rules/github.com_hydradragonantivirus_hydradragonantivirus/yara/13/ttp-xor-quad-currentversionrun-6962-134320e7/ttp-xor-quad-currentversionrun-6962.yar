rule TTP_XOR_QUAD_CurrentVersionRun_6962 {
  strings:
    $key_6962 = { 3a 0d [2] 1e 03 [2] 35 2f [2] 1b 0d [2] 0f 16 [2] 00 0c [2] 1e 11 [2] 1c 10 [2] 07 16 [2] 1b 11 [2] 07 3e }

  condition:
    any of them
}