rule TTP_XOR_QUAD_CurrentVersionRun_05fc {
  strings:
    $key_05fc = { 56 93 [2] 72 9d [2] 59 b1 [2] 77 93 [2] 63 88 [2] 6c 92 [2] 72 8f [2] 70 8e [2] 6b 88 [2] 77 8f [2] 6b a0 }

  condition:
    any of them
}