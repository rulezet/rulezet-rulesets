rule TTP_XOR_QUAD_CurrentVersionRun_e2e9 {
  strings:
    $key_e2e9 = { b1 86 [2] 95 88 [2] be a4 [2] 90 86 [2] 84 9d [2] 8b 87 [2] 95 9a [2] 97 9b [2] 8c 9d [2] 90 9a [2] 8c b5 }

  condition:
    any of them
}