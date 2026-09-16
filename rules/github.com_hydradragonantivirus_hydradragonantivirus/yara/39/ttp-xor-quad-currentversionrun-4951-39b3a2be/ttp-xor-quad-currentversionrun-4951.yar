rule TTP_XOR_QUAD_CurrentVersionRun_4951 {
  strings:
    $key_4951 = { 1a 3e [2] 3e 30 [2] 15 1c [2] 3b 3e [2] 2f 25 [2] 20 3f [2] 3e 22 [2] 3c 23 [2] 27 25 [2] 3b 22 [2] 27 0d }

  condition:
    any of them
}