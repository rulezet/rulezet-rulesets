rule TTP_XOR_QUAD_CurrentVersionRun_e97c {
  strings:
    $key_e97c = { ba 13 [2] 9e 1d [2] b5 31 [2] 9b 13 [2] 8f 08 [2] 80 12 [2] 9e 0f [2] 9c 0e [2] 87 08 [2] 9b 0f [2] 87 20 }

  condition:
    any of them
}