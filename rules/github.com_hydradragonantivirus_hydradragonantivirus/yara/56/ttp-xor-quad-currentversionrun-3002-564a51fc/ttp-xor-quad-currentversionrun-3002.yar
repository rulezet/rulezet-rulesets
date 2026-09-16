rule TTP_XOR_QUAD_CurrentVersionRun_3002 {
  strings:
    $key_3002 = { 63 6d [2] 47 63 [2] 6c 4f [2] 42 6d [2] 56 76 [2] 59 6c [2] 47 71 [2] 45 70 [2] 5e 76 [2] 42 71 [2] 5e 5e }

  condition:
    any of them
}