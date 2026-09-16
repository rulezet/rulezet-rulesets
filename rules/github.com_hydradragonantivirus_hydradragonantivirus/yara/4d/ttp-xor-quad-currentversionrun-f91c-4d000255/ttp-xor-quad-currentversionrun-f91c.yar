rule TTP_XOR_QUAD_CurrentVersionRun_f91c {
  strings:
    $key_f91c = { aa 73 [2] 8e 7d [2] a5 51 [2] 8b 73 [2] 9f 68 [2] 90 72 [2] 8e 6f [2] 8c 6e [2] 97 68 [2] 8b 6f [2] 97 40 }

  condition:
    any of them
}