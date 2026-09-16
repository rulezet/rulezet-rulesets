rule TTP_XOR_QUAD_CurrentVersionRun_34fc {
  strings:
    $key_34fc = { 67 93 [2] 43 9d [2] 68 b1 [2] 46 93 [2] 52 88 [2] 5d 92 [2] 43 8f [2] 41 8e [2] 5a 88 [2] 46 8f [2] 5a a0 }

  condition:
    any of them
}