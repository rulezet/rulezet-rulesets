rule TTP_XOR_QUAD_CurrentVersionRun_6dec {
  strings:
    $key_6dec = { 3e 83 [2] 1a 8d [2] 31 a1 [2] 1f 83 [2] 0b 98 [2] 04 82 [2] 1a 9f [2] 18 9e [2] 03 98 [2] 1f 9f [2] 03 b0 }

  condition:
    any of them
}