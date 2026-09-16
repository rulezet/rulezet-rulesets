rule TTP_XOR_QUAD_CurrentVersionRun_e2e5 {
  strings:
    $key_e2e5 = { b1 8a [2] 95 84 [2] be a8 [2] 90 8a [2] 84 91 [2] 8b 8b [2] 95 96 [2] 97 97 [2] 8c 91 [2] 90 96 [2] 8c b9 }

  condition:
    any of them
}