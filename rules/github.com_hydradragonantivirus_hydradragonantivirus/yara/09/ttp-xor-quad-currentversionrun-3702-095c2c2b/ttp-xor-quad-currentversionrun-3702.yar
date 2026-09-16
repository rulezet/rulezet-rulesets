rule TTP_XOR_QUAD_CurrentVersionRun_3702 {
  strings:
    $key_3702 = { 64 6d [2] 40 63 [2] 6b 4f [2] 45 6d [2] 51 76 [2] 5e 6c [2] 40 71 [2] 42 70 [2] 59 76 [2] 45 71 [2] 59 5e }

  condition:
    any of them
}