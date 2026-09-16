rule TTP_XOR_QUAD_CurrentVersionRun_2efd {
  strings:
    $key_2efd = { 7d 92 [2] 59 9c [2] 72 b0 [2] 5c 92 [2] 48 89 [2] 47 93 [2] 59 8e [2] 5b 8f [2] 40 89 [2] 5c 8e [2] 40 a1 }

  condition:
    any of them
}