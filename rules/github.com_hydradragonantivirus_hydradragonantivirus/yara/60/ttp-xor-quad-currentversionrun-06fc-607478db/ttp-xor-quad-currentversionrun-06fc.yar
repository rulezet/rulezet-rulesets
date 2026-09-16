rule TTP_XOR_QUAD_CurrentVersionRun_06fc {
  strings:
    $key_06fc = { 55 93 [2] 71 9d [2] 5a b1 [2] 74 93 [2] 60 88 [2] 6f 92 [2] 71 8f [2] 73 8e [2] 68 88 [2] 74 8f [2] 68 a0 }

  condition:
    any of them
}