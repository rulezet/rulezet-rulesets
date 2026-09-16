rule TTP_XOR_QUAD_CurrentVersionRun_4bec {
  strings:
    $key_4bec = { 18 83 [2] 3c 8d [2] 17 a1 [2] 39 83 [2] 2d 98 [2] 22 82 [2] 3c 9f [2] 3e 9e [2] 25 98 [2] 39 9f [2] 25 b0 }

  condition:
    any of them
}