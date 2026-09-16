rule TTP_XOR_QUAD_CurrentVersionRun_e9fe {
  strings:
    $key_e9fe = { ba 91 [2] 9e 9f [2] b5 b3 [2] 9b 91 [2] 8f 8a [2] 80 90 [2] 9e 8d [2] 9c 8c [2] 87 8a [2] 9b 8d [2] 87 a2 }

  condition:
    any of them
}