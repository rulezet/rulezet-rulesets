rule TTP_XOR_QUAD_CurrentVersionRun_19ec {
  strings:
    $key_19ec = { 4a 83 [2] 6e 8d [2] 45 a1 [2] 6b 83 [2] 7f 98 [2] 70 82 [2] 6e 9f [2] 6c 9e [2] 77 98 [2] 6b 9f [2] 77 b0 }

  condition:
    any of them
}