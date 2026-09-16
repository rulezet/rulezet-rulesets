rule TTP_XOR_QUAD_CurrentVersionRun_0fec {
  strings:
    $key_0fec = { 5c 83 [2] 78 8d [2] 53 a1 [2] 7d 83 [2] 69 98 [2] 66 82 [2] 78 9f [2] 7a 9e [2] 61 98 [2] 7d 9f [2] 61 b0 }

  condition:
    any of them
}