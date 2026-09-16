rule TTP_XOR_QUAD_CurrentVersionRun_7702 {
  strings:
    $key_7702 = { 24 6d [2] 00 63 [2] 2b 4f [2] 05 6d [2] 11 76 [2] 1e 6c [2] 00 71 [2] 02 70 [2] 19 76 [2] 05 71 [2] 19 5e }

  condition:
    any of them
}