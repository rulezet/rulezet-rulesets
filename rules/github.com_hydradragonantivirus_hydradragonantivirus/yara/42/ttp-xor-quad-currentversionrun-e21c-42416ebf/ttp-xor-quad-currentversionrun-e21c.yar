rule TTP_XOR_QUAD_CurrentVersionRun_e21c {
  strings:
    $key_e21c = { b1 73 [2] 95 7d [2] be 51 [2] 90 73 [2] 84 68 [2] 8b 72 [2] 95 6f [2] 97 6e [2] 8c 68 [2] 90 6f [2] 8c 40 }

  condition:
    any of them
}