rule TTP_XOR_QUAD_CurrentVersionRun_35fc {
  strings:
    $key_35fc = { 66 93 [2] 42 9d [2] 69 b1 [2] 47 93 [2] 53 88 [2] 5c 92 [2] 42 8f [2] 40 8e [2] 5b 88 [2] 47 8f [2] 5b a0 }

  condition:
    any of them
}