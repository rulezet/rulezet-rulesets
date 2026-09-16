rule TTP_XOR_QUAD_CurrentVersionRun_20fc {
  strings:
    $key_20fc = { 73 93 [2] 57 9d [2] 7c b1 [2] 52 93 [2] 46 88 [2] 49 92 [2] 57 8f [2] 55 8e [2] 4e 88 [2] 52 8f [2] 4e a0 }

  condition:
    any of them
}