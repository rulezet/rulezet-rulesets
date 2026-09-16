rule TTP_XOR_QUAD_CurrentVersionRun_3dec {
  strings:
    $key_3dec = { 6e 83 [2] 4a 8d [2] 61 a1 [2] 4f 83 [2] 5b 98 [2] 54 82 [2] 4a 9f [2] 48 9e [2] 53 98 [2] 4f 9f [2] 53 b0 }

  condition:
    any of them
}