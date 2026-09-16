rule TTP_XOR_QUAD_CurrentVersionRun_50fc {
  strings:
    $key_50fc = { 03 93 [2] 27 9d [2] 0c b1 [2] 22 93 [2] 36 88 [2] 39 92 [2] 27 8f [2] 25 8e [2] 3e 88 [2] 22 8f [2] 3e a0 }

  condition:
    any of them
}