rule TTP_XOR_QUAD_CurrentVersionRun_6222 {
  strings:
    $key_6222 = { 31 4d [2] 15 43 [2] 3e 6f [2] 10 4d [2] 04 56 [2] 0b 4c [2] 15 51 [2] 17 50 [2] 0c 56 [2] 10 51 [2] 0c 7e }

  condition:
    any of them
}