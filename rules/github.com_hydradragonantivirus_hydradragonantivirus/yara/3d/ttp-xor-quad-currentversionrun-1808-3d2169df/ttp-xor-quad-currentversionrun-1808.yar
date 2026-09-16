rule TTP_XOR_QUAD_CurrentVersionRun_1808 {
  strings:
    $key_1808 = { 4b 67 [2] 6f 69 [2] 44 45 [2] 6a 67 [2] 7e 7c [2] 71 66 [2] 6f 7b [2] 6d 7a [2] 76 7c [2] 6a 7b [2] 76 54 }

  condition:
    any of them
}