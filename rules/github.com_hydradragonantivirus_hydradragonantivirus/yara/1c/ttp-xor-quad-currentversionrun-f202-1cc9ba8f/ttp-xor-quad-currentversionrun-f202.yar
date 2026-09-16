rule TTP_XOR_QUAD_CurrentVersionRun_f202 {
  strings:
    $key_f202 = { a1 6d [2] 85 63 [2] ae 4f [2] 80 6d [2] 94 76 [2] 9b 6c [2] 85 71 [2] 87 70 [2] 9c 76 [2] 80 71 [2] 9c 5e }

  condition:
    any of them
}