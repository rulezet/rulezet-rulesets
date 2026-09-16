rule TTP_XOR_QUAD_CurrentVersionRun_e966 {
  strings:
    $key_e966 = { ba 09 [2] 9e 07 [2] b5 2b [2] 9b 09 [2] 8f 12 [2] 80 08 [2] 9e 15 [2] 9c 14 [2] 87 12 [2] 9b 15 [2] 87 3a }

  condition:
    any of them
}