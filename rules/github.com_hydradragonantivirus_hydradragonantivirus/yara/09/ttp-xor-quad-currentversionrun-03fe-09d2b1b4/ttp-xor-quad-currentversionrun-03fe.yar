rule TTP_XOR_QUAD_CurrentVersionRun_03fe {
  strings:
    $key_03fe = { 50 91 [2] 74 9f [2] 5f b3 [2] 71 91 [2] 65 8a [2] 6a 90 [2] 74 8d [2] 76 8c [2] 6d 8a [2] 71 8d [2] 6d a2 }

  condition:
    any of them
}