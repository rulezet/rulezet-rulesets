rule TTP_XOR_QUAD_CurrentVersionRun_28fc {
  strings:
    $key_28fc = { 7b 93 [2] 5f 9d [2] 74 b1 [2] 5a 93 [2] 4e 88 [2] 41 92 [2] 5f 8f [2] 5d 8e [2] 46 88 [2] 5a 8f [2] 46 a0 }

  condition:
    any of them
}