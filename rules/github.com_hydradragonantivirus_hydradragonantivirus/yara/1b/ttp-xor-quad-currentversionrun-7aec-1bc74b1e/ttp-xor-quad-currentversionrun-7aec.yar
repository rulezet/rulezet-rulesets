rule TTP_XOR_QUAD_CurrentVersionRun_7aec {
  strings:
    $key_7aec = { 29 83 [2] 0d 8d [2] 26 a1 [2] 08 83 [2] 1c 98 [2] 13 82 [2] 0d 9f [2] 0f 9e [2] 14 98 [2] 08 9f [2] 14 b0 }

  condition:
    any of them
}