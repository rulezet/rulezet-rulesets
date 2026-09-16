rule TTP_XOR_QUAD_CurrentVersionRun_08fc {
  strings:
    $key_08fc = { 5b 93 [2] 7f 9d [2] 54 b1 [2] 7a 93 [2] 6e 88 [2] 61 92 [2] 7f 8f [2] 7d 8e [2] 66 88 [2] 7a 8f [2] 66 a0 }

  condition:
    any of them
}