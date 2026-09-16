rule TTP_XOR_QUAD_CurrentVersionRun_16f0 {
  strings:
    $key_16f0 = { 45 9f [2] 61 91 [2] 4a bd [2] 64 9f [2] 70 84 [2] 7f 9e [2] 61 83 [2] 63 82 [2] 78 84 [2] 64 83 [2] 78 ac }

  condition:
    any of them
}