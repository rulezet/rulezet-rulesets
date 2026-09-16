rule TTP_XOR_QUAD_CurrentVersionRun_72ec {
  strings:
    $key_72ec = { 21 83 [2] 05 8d [2] 2e a1 [2] 00 83 [2] 14 98 [2] 1b 82 [2] 05 9f [2] 07 9e [2] 1c 98 [2] 00 9f [2] 1c b0 }

  condition:
    any of them
}