rule TTP_XOR_QUAD_CurrentVersionRun_7dec {
  strings:
    $key_7dec = { 2e 83 [2] 0a 8d [2] 21 a1 [2] 0f 83 [2] 1b 98 [2] 14 82 [2] 0a 9f [2] 08 9e [2] 13 98 [2] 0f 9f [2] 13 b0 }

  condition:
    any of them
}