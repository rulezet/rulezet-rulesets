rule TTP_XOR_QUAD_CurrentVersionRun_19fd {
  strings:
    $key_19fd = { 4a 92 [2] 6e 9c [2] 45 b0 [2] 6b 92 [2] 7f 89 [2] 70 93 [2] 6e 8e [2] 6c 8f [2] 77 89 [2] 6b 8e [2] 77 a1 }

  condition:
    any of them
}