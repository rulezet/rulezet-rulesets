rule TTP_XOR_QUAD_CurrentVersionRun_f0fc {
  strings:
    $key_f0fc = { a3 93 [2] 87 9d [2] ac b1 [2] 82 93 [2] 96 88 [2] 99 92 [2] 87 8f [2] 85 8e [2] 9e 88 [2] 82 8f [2] 9e a0 }

  condition:
    any of them
}