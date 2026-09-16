rule TTP_XOR_QUAD_CurrentVersionRun_e934 {
  strings:
    $key_e934 = { ba 5b [2] 9e 55 [2] b5 79 [2] 9b 5b [2] 8f 40 [2] 80 5a [2] 9e 47 [2] 9c 46 [2] 87 40 [2] 9b 47 [2] 87 68 }

  condition:
    any of them
}