rule TTP_XOR_QUAD_CurrentVersionRun_e21f {
  strings:
    $key_e21f = { b1 70 [2] 95 7e [2] be 52 [2] 90 70 [2] 84 6b [2] 8b 71 [2] 95 6c [2] 97 6d [2] 8c 6b [2] 90 6c [2] 8c 43 }

  condition:
    any of them
}