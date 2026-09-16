rule TTP_XOR_QUAD_CurrentVersionRun_f933 {
  strings:
    $key_f933 = { aa 5c [2] 8e 52 [2] a5 7e [2] 8b 5c [2] 9f 47 [2] 90 5d [2] 8e 40 [2] 8c 41 [2] 97 47 [2] 8b 40 [2] 97 6f }

  condition:
    any of them
}