rule TTP_XOR_QUAD_CurrentVersionRun_e91d {
  strings:
    $key_e91d = { ba 72 [2] 9e 7c [2] b5 50 [2] 9b 72 [2] 8f 69 [2] 80 73 [2] 9e 6e [2] 9c 6f [2] 87 69 [2] 9b 6e [2] 87 41 }

  condition:
    any of them
}