rule TTP_XOR_QUAD_CurrentVersionRun_38ed {
  strings:
    $key_38ed = { 6b 82 [2] 4f 8c [2] 64 a0 [2] 4a 82 [2] 5e 99 [2] 51 83 [2] 4f 9e [2] 4d 9f [2] 56 99 [2] 4a 9e [2] 56 b1 }

  condition:
    any of them
}