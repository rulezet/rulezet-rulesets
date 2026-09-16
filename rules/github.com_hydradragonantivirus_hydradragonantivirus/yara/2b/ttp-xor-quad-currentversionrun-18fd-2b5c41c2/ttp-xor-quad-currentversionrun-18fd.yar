rule TTP_XOR_QUAD_CurrentVersionRun_18fd {
  strings:
    $key_18fd = { 4b 92 [2] 6f 9c [2] 44 b0 [2] 6a 92 [2] 7e 89 [2] 71 93 [2] 6f 8e [2] 6d 8f [2] 76 89 [2] 6a 8e [2] 76 a1 }

  condition:
    any of them
}