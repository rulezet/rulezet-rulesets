rule TTP_XOR_QUAD_CurrentVersionRun_e216 {
  strings:
    $key_e216 = { b1 79 [2] 95 77 [2] be 5b [2] 90 79 [2] 84 62 [2] 8b 78 [2] 95 65 [2] 97 64 [2] 8c 62 [2] 90 65 [2] 8c 4a }

  condition:
    any of them
}