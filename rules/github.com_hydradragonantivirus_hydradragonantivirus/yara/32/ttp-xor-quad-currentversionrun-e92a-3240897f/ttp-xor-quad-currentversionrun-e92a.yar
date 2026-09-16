rule TTP_XOR_QUAD_CurrentVersionRun_e92a {
  strings:
    $key_e92a = { ba 45 [2] 9e 4b [2] b5 67 [2] 9b 45 [2] 8f 5e [2] 80 44 [2] 9e 59 [2] 9c 58 [2] 87 5e [2] 9b 59 [2] 87 76 }

  condition:
    any of them
}