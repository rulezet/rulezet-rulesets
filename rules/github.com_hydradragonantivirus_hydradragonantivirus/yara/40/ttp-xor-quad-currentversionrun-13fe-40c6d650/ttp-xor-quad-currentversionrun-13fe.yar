rule TTP_XOR_QUAD_CurrentVersionRun_13fe {
  strings:
    $key_13fe = { 40 91 [2] 64 9f [2] 4f b3 [2] 61 91 [2] 75 8a [2] 7a 90 [2] 64 8d [2] 66 8c [2] 7d 8a [2] 61 8d [2] 7d a2 }

  condition:
    any of them
}