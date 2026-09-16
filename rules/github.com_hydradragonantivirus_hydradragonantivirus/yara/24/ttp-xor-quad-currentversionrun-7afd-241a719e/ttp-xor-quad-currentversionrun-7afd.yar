rule TTP_XOR_QUAD_CurrentVersionRun_7afd {
  strings:
    $key_7afd = { 29 92 [2] 0d 9c [2] 26 b0 [2] 08 92 [2] 1c 89 [2] 13 93 [2] 0d 8e [2] 0f 8f [2] 14 89 [2] 08 8e [2] 14 a1 }

  condition:
    any of them
}