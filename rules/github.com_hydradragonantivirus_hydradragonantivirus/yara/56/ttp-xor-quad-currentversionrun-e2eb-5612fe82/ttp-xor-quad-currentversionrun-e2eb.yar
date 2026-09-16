rule TTP_XOR_QUAD_CurrentVersionRun_e2eb {
  strings:
    $key_e2eb = { b1 84 [2] 95 8a [2] be a6 [2] 90 84 [2] 84 9f [2] 8b 85 [2] 95 98 [2] 97 99 [2] 8c 9f [2] 90 98 [2] 8c b7 }

  condition:
    any of them
}