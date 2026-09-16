rule TTP_XOR_QUAD_CurrentVersionRun_e2f0 {
  strings:
    $key_e2f0 = { b1 9f [2] 95 91 [2] be bd [2] 90 9f [2] 84 84 [2] 8b 9e [2] 95 83 [2] 97 82 [2] 8c 84 [2] 90 83 [2] 8c ac }

  condition:
    any of them
}