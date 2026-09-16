rule TTP_XOR_QUAD_CurrentVersionRun_24ec {
  strings:
    $key_24ec = { 77 83 [2] 53 8d [2] 78 a1 [2] 56 83 [2] 42 98 [2] 4d 82 [2] 53 9f [2] 51 9e [2] 4a 98 [2] 56 9f [2] 4a b0 }

  condition:
    any of them
}