rule TTP_XOR_QUAD_CurrentVersionRun_e278 {
  strings:
    $key_e278 = { b1 17 [2] 95 19 [2] be 35 [2] 90 17 [2] 84 0c [2] 8b 16 [2] 95 0b [2] 97 0a [2] 8c 0c [2] 90 0b [2] 8c 24 }

  condition:
    any of them
}