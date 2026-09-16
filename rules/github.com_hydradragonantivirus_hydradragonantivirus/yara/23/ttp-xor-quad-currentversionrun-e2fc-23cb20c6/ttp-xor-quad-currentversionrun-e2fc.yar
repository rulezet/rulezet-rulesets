rule TTP_XOR_QUAD_CurrentVersionRun_e2fc {
  strings:
    $key_e2fc = { b1 93 [2] 95 9d [2] be b1 [2] 90 93 [2] 84 88 [2] 8b 92 [2] 95 8f [2] 97 8e [2] 8c 88 [2] 90 8f [2] 8c a0 }

  condition:
    any of them
}