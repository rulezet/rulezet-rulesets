rule TTP_XOR_QUAD_CurrentVersionRun_02fc {
  strings:
    $key_02fc = { 51 93 [2] 75 9d [2] 5e b1 [2] 70 93 [2] 64 88 [2] 6b 92 [2] 75 8f [2] 77 8e [2] 6c 88 [2] 70 8f [2] 6c a0 }

  condition:
    any of them
}