rule TTP_XOR_QUAD_CurrentVersionRun_1221 {
  strings:
    $key_1221 = { 41 4e [2] 65 40 [2] 4e 6c [2] 60 4e [2] 74 55 [2] 7b 4f [2] 65 52 [2] 67 53 [2] 7c 55 [2] 60 52 [2] 7c 7d }

  condition:
    any of them
}