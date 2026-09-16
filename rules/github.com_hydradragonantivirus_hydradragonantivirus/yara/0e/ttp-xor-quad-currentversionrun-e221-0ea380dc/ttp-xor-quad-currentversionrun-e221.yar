rule TTP_XOR_QUAD_CurrentVersionRun_e221 {
  strings:
    $key_e221 = { b1 4e [2] 95 40 [2] be 6c [2] 90 4e [2] 84 55 [2] 8b 4f [2] 95 52 [2] 97 53 [2] 8c 55 [2] 90 52 [2] 8c 7d }

  condition:
    any of them
}