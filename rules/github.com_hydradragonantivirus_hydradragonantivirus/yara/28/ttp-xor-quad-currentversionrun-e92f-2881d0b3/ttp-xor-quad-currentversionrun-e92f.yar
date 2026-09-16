rule TTP_XOR_QUAD_CurrentVersionRun_e92f {
  strings:
    $key_e92f = { ba 40 [2] 9e 4e [2] b5 62 [2] 9b 40 [2] 8f 5b [2] 80 41 [2] 9e 5c [2] 9c 5d [2] 87 5b [2] 9b 5c [2] 87 73 }

  condition:
    any of them
}