rule TTP_XOR_QUAD_CurrentVersionRun_05ec {
  strings:
    $key_05ec = { 56 83 [2] 72 8d [2] 59 a1 [2] 77 83 [2] 63 98 [2] 6c 82 [2] 72 9f [2] 70 9e [2] 6b 98 [2] 77 9f [2] 6b b0 }

  condition:
    any of them
}