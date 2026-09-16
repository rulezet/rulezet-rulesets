rule TTP_XOR_QUAD_CurrentVersionRun_32ef {
  strings:
    $key_32ef = { 61 80 [2] 45 8e [2] 6e a2 [2] 40 80 [2] 54 9b [2] 5b 81 [2] 45 9c [2] 47 9d [2] 5c 9b [2] 40 9c [2] 5c b3 }

  condition:
    any of them
}