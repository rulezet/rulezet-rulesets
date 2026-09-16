rule TTP_XOR_QUAD_CurrentVersionRun_01ec {
  strings:
    $key_01ec = { 52 83 [2] 76 8d [2] 5d a1 [2] 73 83 [2] 67 98 [2] 68 82 [2] 76 9f [2] 74 9e [2] 6f 98 [2] 73 9f [2] 6f b0 }

  condition:
    any of them
}