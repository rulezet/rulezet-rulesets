rule TTP_XOR_QUAD_CurrentVersionRun_3076 {
  strings:
    $key_3076 = { 63 19 [2] 47 17 [2] 6c 3b [2] 42 19 [2] 56 02 [2] 59 18 [2] 47 05 [2] 45 04 [2] 5e 02 [2] 42 05 [2] 5e 2a }

  condition:
    any of them
}