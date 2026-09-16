rule TTP_XOR_QUAD_CurrentVersionRun_e211 {
  strings:
    $key_e211 = { b1 7e [2] 95 70 [2] be 5c [2] 90 7e [2] 84 65 [2] 8b 7f [2] 95 62 [2] 97 63 [2] 8c 65 [2] 90 62 [2] 8c 4d }

  condition:
    any of them
}