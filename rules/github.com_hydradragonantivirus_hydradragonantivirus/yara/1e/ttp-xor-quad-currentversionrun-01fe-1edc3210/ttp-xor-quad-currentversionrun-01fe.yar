rule TTP_XOR_QUAD_CurrentVersionRun_01fe {
  strings:
    $key_01fe = { 52 91 [2] 76 9f [2] 5d b3 [2] 73 91 [2] 67 8a [2] 68 90 [2] 76 8d [2] 74 8c [2] 6f 8a [2] 73 8d [2] 6f a2 }

  condition:
    any of them
}