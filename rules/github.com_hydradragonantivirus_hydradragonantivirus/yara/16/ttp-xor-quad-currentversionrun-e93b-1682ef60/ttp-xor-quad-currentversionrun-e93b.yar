rule TTP_XOR_QUAD_CurrentVersionRun_e93b {
  strings:
    $key_e93b = { ba 54 [2] 9e 5a [2] b5 76 [2] 9b 54 [2] 8f 4f [2] 80 55 [2] 9e 48 [2] 9c 49 [2] 87 4f [2] 9b 48 [2] 87 67 }

  condition:
    any of them
}