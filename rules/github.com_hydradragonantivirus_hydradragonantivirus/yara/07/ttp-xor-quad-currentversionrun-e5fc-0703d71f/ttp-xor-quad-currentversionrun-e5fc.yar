rule TTP_XOR_QUAD_CurrentVersionRun_e5fc {
  strings:
    $key_e5fc = { b6 93 [2] 92 9d [2] b9 b1 [2] 97 93 [2] 83 88 [2] 8c 92 [2] 92 8f [2] 90 8e [2] 8b 88 [2] 97 8f [2] 8b a0 }

  condition:
    any of them
}