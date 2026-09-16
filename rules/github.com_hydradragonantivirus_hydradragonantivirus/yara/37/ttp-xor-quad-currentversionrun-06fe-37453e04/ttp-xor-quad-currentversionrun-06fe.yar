rule TTP_XOR_QUAD_CurrentVersionRun_06fe {
  strings:
    $key_06fe = { 55 91 [2] 71 9f [2] 5a b3 [2] 74 91 [2] 60 8a [2] 6f 90 [2] 71 8d [2] 73 8c [2] 68 8a [2] 74 8d [2] 68 a2 }

  condition:
    any of them
}