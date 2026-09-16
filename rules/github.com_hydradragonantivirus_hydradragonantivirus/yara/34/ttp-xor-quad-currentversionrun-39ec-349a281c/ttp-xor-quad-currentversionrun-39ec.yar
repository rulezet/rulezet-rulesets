rule TTP_XOR_QUAD_CurrentVersionRun_39ec {
  strings:
    $key_39ec = { 6a 83 [2] 4e 8d [2] 65 a1 [2] 4b 83 [2] 5f 98 [2] 50 82 [2] 4e 9f [2] 4c 9e [2] 57 98 [2] 4b 9f [2] 57 b0 }

  condition:
    any of them
}