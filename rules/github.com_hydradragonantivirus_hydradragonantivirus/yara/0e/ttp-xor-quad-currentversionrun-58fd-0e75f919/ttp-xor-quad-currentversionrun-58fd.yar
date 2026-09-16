rule TTP_XOR_QUAD_CurrentVersionRun_58fd {
  strings:
    $key_58fd = { 0b 92 [2] 2f 9c [2] 04 b0 [2] 2a 92 [2] 3e 89 [2] 31 93 [2] 2f 8e [2] 2d 8f [2] 36 89 [2] 2a 8e [2] 36 a1 }

  condition:
    any of them
}