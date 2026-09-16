rule TTP_XOR_QUAD_CurrentVersionRun_0d72 {
  strings:
    $key_0d72 = { 5e 1d [2] 7a 13 [2] 51 3f [2] 7f 1d [2] 6b 06 [2] 64 1c [2] 7a 01 [2] 78 00 [2] 63 06 [2] 7f 01 [2] 63 2e }

  condition:
    any of them
}