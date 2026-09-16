rule TTP_XOR_QUAD_CurrentVersionRun_57ec {
  strings:
    $key_57ec = { 04 83 [2] 20 8d [2] 0b a1 [2] 25 83 [2] 31 98 [2] 3e 82 [2] 20 9f [2] 22 9e [2] 39 98 [2] 25 9f [2] 39 b0 }

  condition:
    any of them
}