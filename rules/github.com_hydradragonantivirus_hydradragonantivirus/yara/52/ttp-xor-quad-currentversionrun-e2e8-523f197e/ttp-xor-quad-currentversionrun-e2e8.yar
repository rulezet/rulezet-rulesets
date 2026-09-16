rule TTP_XOR_QUAD_CurrentVersionRun_e2e8 {
  strings:
    $key_e2e8 = { b1 87 [2] 95 89 [2] be a5 [2] 90 87 [2] 84 9c [2] 8b 86 [2] 95 9b [2] 97 9a [2] 8c 9c [2] 90 9b [2] 8c b4 }

  condition:
    any of them
}