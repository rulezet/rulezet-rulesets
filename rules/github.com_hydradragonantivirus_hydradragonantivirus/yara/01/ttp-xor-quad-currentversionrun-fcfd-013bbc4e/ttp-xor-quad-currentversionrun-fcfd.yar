rule TTP_XOR_QUAD_CurrentVersionRun_fcfd {
  strings:
    $key_fcfd = { af 92 [2] 8b 9c [2] a0 b0 [2] 8e 92 [2] 9a 89 [2] 95 93 [2] 8b 8e [2] 89 8f [2] 92 89 [2] 8e 8e [2] 92 a1 }

  condition:
    any of them
}