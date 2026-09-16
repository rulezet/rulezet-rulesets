rule TTP_XOR_QUAD_CurrentVersionRun_0602 {
  strings:
    $key_0602 = { 55 6d [2] 71 63 [2] 5a 4f [2] 74 6d [2] 60 76 [2] 6f 6c [2] 71 71 [2] 73 70 [2] 68 76 [2] 74 71 [2] 68 5e }

  condition:
    any of them
}