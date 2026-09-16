rule TTP_XOR_QUAD_CurrentVersionRun_39fc {
  strings:
    $key_39fc = { 6a 93 [2] 4e 9d [2] 65 b1 [2] 4b 93 [2] 5f 88 [2] 50 92 [2] 4e 8f [2] 4c 8e [2] 57 88 [2] 4b 8f [2] 57 a0 }

  condition:
    any of them
}