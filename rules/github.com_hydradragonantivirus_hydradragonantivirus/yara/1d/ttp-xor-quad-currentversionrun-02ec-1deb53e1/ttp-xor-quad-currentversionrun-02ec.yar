rule TTP_XOR_QUAD_CurrentVersionRun_02ec {
  strings:
    $key_02ec = { 51 83 [2] 75 8d [2] 5e a1 [2] 70 83 [2] 64 98 [2] 6b 82 [2] 75 9f [2] 77 9e [2] 6c 98 [2] 70 9f [2] 6c b0 }

  condition:
    any of them
}