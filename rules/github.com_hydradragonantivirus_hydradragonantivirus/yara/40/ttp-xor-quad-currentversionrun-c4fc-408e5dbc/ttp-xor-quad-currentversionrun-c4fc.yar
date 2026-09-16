rule TTP_XOR_QUAD_CurrentVersionRun_c4fc {
  strings:
    $key_c4fc = { 97 93 [2] b3 9d [2] 98 b1 [2] b6 93 [2] a2 88 [2] ad 92 [2] b3 8f [2] b1 8e [2] aa 88 [2] b6 8f [2] aa a0 }

  condition:
    any of them
}