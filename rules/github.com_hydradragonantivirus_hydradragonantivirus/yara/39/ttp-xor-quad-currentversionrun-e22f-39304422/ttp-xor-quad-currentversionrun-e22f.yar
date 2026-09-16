rule TTP_XOR_QUAD_CurrentVersionRun_e22f {
  strings:
    $key_e22f = { b1 40 [2] 95 4e [2] be 62 [2] 90 40 [2] 84 5b [2] 8b 41 [2] 95 5c [2] 97 5d [2] 8c 5b [2] 90 5c [2] 8c 73 }

  condition:
    any of them
}