rule TTP_XOR_QUAD_CurrentVersionRun_7512 {
  strings:
    $key_7512 = { 26 7d [2] 02 73 [2] 29 5f [2] 07 7d [2] 13 66 [2] 1c 7c [2] 02 61 [2] 00 60 [2] 1b 66 [2] 07 61 [2] 1b 4e }

  condition:
    any of them
}