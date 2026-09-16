rule TTP_XOR_QUAD_CurrentVersionRun_2fed {
  strings:
    $key_2fed = { 7c 82 [2] 58 8c [2] 73 a0 [2] 5d 82 [2] 49 99 [2] 46 83 [2] 58 9e [2] 5a 9f [2] 41 99 [2] 5d 9e [2] 41 b1 }

  condition:
    any of them
}