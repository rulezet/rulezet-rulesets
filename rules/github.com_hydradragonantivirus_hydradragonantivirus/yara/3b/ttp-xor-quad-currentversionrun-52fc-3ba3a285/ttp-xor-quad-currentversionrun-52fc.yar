rule TTP_XOR_QUAD_CurrentVersionRun_52fc {
  strings:
    $key_52fc = { 01 93 [2] 25 9d [2] 0e b1 [2] 20 93 [2] 34 88 [2] 3b 92 [2] 25 8f [2] 27 8e [2] 3c 88 [2] 20 8f [2] 3c a0 }

  condition:
    any of them
}