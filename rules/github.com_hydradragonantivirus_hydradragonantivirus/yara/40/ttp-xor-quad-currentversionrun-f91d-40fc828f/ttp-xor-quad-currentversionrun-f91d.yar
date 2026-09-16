rule TTP_XOR_QUAD_CurrentVersionRun_f91d {
  strings:
    $key_f91d = { aa 72 [2] 8e 7c [2] a5 50 [2] 8b 72 [2] 9f 69 [2] 90 73 [2] 8e 6e [2] 8c 6f [2] 97 69 [2] 8b 6e [2] 97 41 }

  condition:
    any of them
}