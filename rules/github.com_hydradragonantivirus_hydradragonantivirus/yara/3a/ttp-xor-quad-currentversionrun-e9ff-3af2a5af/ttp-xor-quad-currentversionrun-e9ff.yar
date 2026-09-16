rule TTP_XOR_QUAD_CurrentVersionRun_e9ff {
  strings:
    $key_e9ff = { ba 90 [2] 9e 9e [2] b5 b2 [2] 9b 90 [2] 8f 8b [2] 80 91 [2] 9e 8c [2] 9c 8d [2] 87 8b [2] 9b 8c [2] 87 a3 }

  condition:
    any of them
}