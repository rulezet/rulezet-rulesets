rule TTP_XOR_QUAD_CurrentVersionRun_e24f {
  strings:
    $key_e24f = { b1 20 [2] 95 2e [2] be 02 [2] 90 20 [2] 84 3b [2] 8b 21 [2] 95 3c [2] 97 3d [2] 8c 3b [2] 90 3c [2] 8c 13 }

  condition:
    any of them
}