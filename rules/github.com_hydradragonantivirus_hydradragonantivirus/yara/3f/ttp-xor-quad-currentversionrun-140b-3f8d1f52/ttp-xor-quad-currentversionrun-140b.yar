rule TTP_XOR_QUAD_CurrentVersionRun_140b {
  strings:
    $key_140b = { 47 64 [2] 63 6a [2] 48 46 [2] 66 64 [2] 72 7f [2] 7d 65 [2] 63 78 [2] 61 79 [2] 7a 7f [2] 66 78 [2] 7a 57 }

  condition:
    any of them
}