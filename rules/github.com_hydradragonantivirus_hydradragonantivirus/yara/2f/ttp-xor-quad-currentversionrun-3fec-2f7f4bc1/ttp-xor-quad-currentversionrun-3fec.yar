rule TTP_XOR_QUAD_CurrentVersionRun_3fec {
  strings:
    $key_3fec = { 6c 83 [2] 48 8d [2] 63 a1 [2] 4d 83 [2] 59 98 [2] 56 82 [2] 48 9f [2] 4a 9e [2] 51 98 [2] 4d 9f [2] 51 b0 }

  condition:
    any of them
}