rule TTP_XOR_QUAD_CurrentVersionRun_36fc {
  strings:
    $key_36fc = { 65 93 [2] 41 9d [2] 6a b1 [2] 44 93 [2] 50 88 [2] 5f 92 [2] 41 8f [2] 43 8e [2] 58 88 [2] 44 8f [2] 58 a0 }

  condition:
    any of them
}