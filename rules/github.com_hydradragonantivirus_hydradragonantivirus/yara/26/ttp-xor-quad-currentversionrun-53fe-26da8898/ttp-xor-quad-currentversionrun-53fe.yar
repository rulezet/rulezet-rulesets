rule TTP_XOR_QUAD_CurrentVersionRun_53fe {
  strings:
    $key_53fe = { 00 91 [2] 24 9f [2] 0f b3 [2] 21 91 [2] 35 8a [2] 3a 90 [2] 24 8d [2] 26 8c [2] 3d 8a [2] 21 8d [2] 3d a2 }

  condition:
    any of them
}