rule TTP_XOR_QUAD_CurrentVersionRun_f9ec {
  strings:
    $key_f9ec = { aa 83 [2] 8e 8d [2] a5 a1 [2] 8b 83 [2] 9f 98 [2] 90 82 [2] 8e 9f [2] 8c 9e [2] 97 98 [2] 8b 9f [2] 97 b0 }

  condition:
    any of them
}