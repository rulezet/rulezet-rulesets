rule TTP_XOR_QUAD_CurrentVersionRun_0e02 {
  strings:
    $key_0e02 = { 5d 6d [2] 79 63 [2] 52 4f [2] 7c 6d [2] 68 76 [2] 67 6c [2] 79 71 [2] 7b 70 [2] 60 76 [2] 7c 71 [2] 60 5e }

  condition:
    any of them
}