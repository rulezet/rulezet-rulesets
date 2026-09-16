rule TTP_XOR_QUAD_CurrentVersionRun_1dfe {
  strings:
    $key_1dfe = { 4e 91 [2] 6a 9f [2] 41 b3 [2] 6f 91 [2] 7b 8a [2] 74 90 [2] 6a 8d [2] 68 8c [2] 73 8a [2] 6f 8d [2] 73 a2 }

  condition:
    any of them
}