rule TTP_XOR_QUAD_CurrentVersionRun_0fed {
  strings:
    $key_0fed = { 5c 82 [2] 78 8c [2] 53 a0 [2] 7d 82 [2] 69 99 [2] 66 83 [2] 78 9e [2] 7a 9f [2] 61 99 [2] 7d 9e [2] 61 b1 }

  condition:
    any of them
}